package carver

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"testing"

	"github.com/edcamero13/disk-recover/internal/output"
	"github.com/edcamero13/disk-recover/internal/signatures"
	"github.com/edcamero13/disk-recover/pkg/magic"
)

// memWriter recoge en memoria lo que el carver quiere escribir. Como Carver
// acepta la interfaz Writer, se puede testear entero sin tocar el disco.
type memWriter struct {
	names []string
	data  [][]byte
}

func (w *memWriter) Save(r io.Reader, desiredName string) (*output.WriteResult, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	w.names = append(w.names, desiredName)
	w.data = append(w.data, data)

	return &output.WriteResult{
		FinalPath: "/mem/" + desiredName,
		Size:      int64(len(data)),
		SHA256:    fmt.Sprintf("%x", sha256.Sum256(data)),
	}, nil
}

// jpeg construye un JPEG sintético del tamaño pedido, con su header y su footer.
func jpeg(size int) []byte {
	if size < 5 {
		size = 5
	}
	b := make([]byte, size)
	copy(b, []byte{0xFF, 0xD8, 0xFF, 0xE0})
	for i := 4; i < size-2; i++ {
		b[i] = byte(i % 250) // relleno sin 0xFF D9 accidentales
	}
	copy(b[size-2:], []byte{0xFF, 0xD9})
	return b
}

func jpegRegistry(t *testing.T) *signatures.Registry {
	t.Helper()
	reg := signatures.NewRegistry()
	err := reg.Register(signatures.Signature{
		Name: "jpeg", Extension: ".jpg", Category: "image",
		Header:  magic.MustParse("FF D8 FF"),
		Footer:  []byte{0xFF, 0xD9},
		MaxSize: 50 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

func TestCarveJPEG(t *testing.T) {
	const at = 4096
	photo := jpeg(2000)

	disk := make([]byte, 64<<10)
	copy(disk[at:], photo)

	w := &memWriter{}
	c := New(bytes.NewReader(disk), int64(len(disk)), w, jpegRegistry(t))

	results, err := c.Run()
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("se extrajeron %d archivos, se esperaba 1", len(results))
	}

	if results[0].Offset != at {
		t.Errorf("Offset = %d, se esperaba %d", results[0].Offset, at)
	}
	if !bytes.Equal(w.data[0], photo) {
		t.Errorf("el contenido extraído (%d bytes) no coincide con el original (%d bytes)",
			len(w.data[0]), len(photo))
	}
}

// TestCarveCrossBlock es la prueba que el enunciado de la auditoría pedía: una
// firma cuyo cuerpo cruza el límite de bloque de 1 MB. El header cae al final
// de un bloque y el footer muy por delante, fuera incluso de los 64 KB de
// solape, así que solo funciona si findSize lee del origen y no del bloque.
func TestCarveCrossBlock(t *testing.T) {
	const at = blockSize - 10 // el header arranca justo antes del corte
	photo := jpeg(300 << 10)  // 300 KB: el footer queda muy lejos del solape

	disk := make([]byte, 3*blockSize)
	copy(disk[at:], photo)

	w := &memWriter{}
	c := New(bytes.NewReader(disk), int64(len(disk)), w, jpegRegistry(t))

	results, err := c.Run()
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("se extrajeron %d archivos, se esperaba 1", len(results))
	}
	if results[0].Offset != at {
		t.Errorf("Offset = %d, se esperaba %d", results[0].Offset, at)
	}
	if !bytes.Equal(w.data[0], photo) {
		t.Errorf("el archivo a caballo del bloque se extrajo mal: %d bytes de %d",
			len(w.data[0]), len(photo))
	}
}

// TestCarveNoDuplicatesInOverlap es la regresión de [I2]. La zona de solape se
// entrega DOS veces al carver (así se encuentran las firmas del borde), pero
// sin deduplicar eso produce dos copias idénticas del mismo archivo.
func TestCarveNoDuplicatesInOverlap(t *testing.T) {
	// Dentro de los 64 KB de solape que siguen al primer bloque.
	const at = blockSize + 1000
	photo := jpeg(500)

	disk := make([]byte, 3*blockSize)
	copy(disk[at:], photo)

	w := &memWriter{}
	c := New(bytes.NewReader(disk), int64(len(disk)), w, jpegRegistry(t))

	results, err := c.Run()
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("se extrajeron %d archivos, se esperaba 1: la zona de solape "+
			"produjo duplicados (nombres: %v)", len(results), w.names)
	}
}

// TestCarveSkipsEmbeddedThumbnail: la miniatura dentro del EXIF de un JPEG es
// otro JPEG. Sin processedUntil se extraería como archivo independiente.
func TestCarveSkipsEmbeddedThumbnail(t *testing.T) {
	photo := jpeg(20000)
	// Incrustar una firma JPEG dentro del cuerpo, como haría una miniatura.
	copy(photo[5000:], []byte{0xFF, 0xD8, 0xFF, 0xE1})

	disk := make([]byte, 64<<10)
	copy(disk[1000:], photo)

	w := &memWriter{}
	c := New(bytes.NewReader(disk), int64(len(disk)), w, jpegRegistry(t))

	results, err := c.Run()
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("se extrajeron %d archivos, se esperaba 1: la miniatura incrustada "+
			"se está tratando como archivo aparte", len(results))
	}
}

// TestCarveHeaderWithoutFooterIsSkipped: un header suelto sin su footer es casi
// siempre un falso positivo. Extraer MaxSize bytes de basura por cada uno llena
// el destino sin recuperar nada.
func TestCarveHeaderWithoutFooterIsSkipped(t *testing.T) {
	disk := make([]byte, 64<<10)
	copy(disk[1000:], []byte{0xFF, 0xD8, 0xFF, 0xE0}) // header, sin FF D9 después

	w := &memWriter{}
	c := New(bytes.NewReader(disk), int64(len(disk)), w, jpegRegistry(t))

	results, err := c.Run()
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("se extrajeron %d archivos de un header sin footer, se esperaban 0", len(results))
	}
}

// TestCarveNoFooterUsesMaxSize: para las firmas que no declaran footer (MP4,
// por ejemplo) el tope es MaxSize, recortado al final del origen.
func TestCarveNoFooterUsesMaxSize(t *testing.T) {
	reg := signatures.NewRegistry()
	if err := reg.Register(signatures.Signature{
		Name: "raw", Extension: ".raw", Category: "test",
		Header:  magic.MustParse("DE AD BE EF"),
		MaxSize: 4096,
	}); err != nil {
		t.Fatal(err)
	}

	disk := make([]byte, 64<<10)
	copy(disk[100:], []byte{0xDE, 0xAD, 0xBE, 0xEF})

	w := &memWriter{}
	c := New(bytes.NewReader(disk), int64(len(disk)), w, reg)

	results, err := c.Run()
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("se extrajeron %d archivos, se esperaba 1", len(results))
	}
	if results[0].Size != 4096 {
		t.Errorf("Size = %d, se esperaba MaxSize (4096)", results[0].Size)
	}
}

// TestCarveZeroDiskProducesNothing es la regresión de [C10]. Con la firma de
// MP4 puesta en {0x00,0x00,0x00}, un disco formateado (todo ceros por
// definición) generaba millones de coincidencias, cada una pidiendo hasta 4 GB.
func TestCarveZeroDiskProducesNothing(t *testing.T) {
	disk := make([]byte, 2*blockSize) // 2 MB de ceros

	w := &memWriter{}
	c := New(bytes.NewReader(disk), int64(len(disk)), w, signatures.DefaultRegistry())

	results, err := c.Run()
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("un disco de ceros produjo %d archivos, se esperaban 0 "+
			"(primeros nombres: %v)", len(results), w.names[:min(5, len(w.names))])
	}
}

func TestCarveMultipleFiles(t *testing.T) {
	disk := make([]byte, 256<<10)
	offsets := []int{1000, 20000, 90000, 150000}
	for _, off := range offsets {
		copy(disk[off:], jpeg(3000))
	}

	w := &memWriter{}
	c := New(bytes.NewReader(disk), int64(len(disk)), w, jpegRegistry(t))

	results, err := c.Run()
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(results) != len(offsets) {
		t.Fatalf("se extrajeron %d archivos, se esperaban %d", len(results), len(offsets))
	}
	for i, want := range offsets {
		if results[i].Offset != int64(want) {
			t.Errorf("archivo %d: Offset = %d, se esperaba %d", i, results[i].Offset, want)
		}
	}
}

func TestCarveRequiresWriter(t *testing.T) {
	c := New(bytes.NewReader(make([]byte, 100)), 100, nil, nil)
	if _, err := c.Run(); err == nil {
		t.Error("se esperaba error al no pasar Writer")
	}
}

func TestCarveCancellation(t *testing.T) {
	disk := make([]byte, 4*blockSize)
	copy(disk[1000:], jpeg(2000))

	cancel := make(chan struct{})
	close(cancel)

	w := &memWriter{}
	c := New(bytes.NewReader(disk), int64(len(disk)), w, jpegRegistry(t))
	c.SetCancelChannel(cancel)

	if _, err := c.Run(); err == nil {
		t.Error("se esperaba error de cancelación")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
