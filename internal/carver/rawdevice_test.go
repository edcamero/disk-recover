package carver

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	"github.com/edcamero/disk-recover/internal/blockdev"
	"github.com/edcamero/disk-recover/internal/output"
	"github.com/edcamero/disk-recover/internal/signatures"
	"github.com/edcamero/disk-recover/pkg/magic"
)

// strictDevice imita \.\PhysicalDriveN en Windows: rechaza toda lectura cuyo
// offset o longitud no sean multiplos del sector.
type strictDevice struct {
	data    []byte
	sector  int64
	rejects []string
}

func (d *strictDevice) ReadAt(p []byte, off int64) (int, error) {
	if off%d.sector != 0 || int64(len(p))%d.sector != 0 {
		d.rejects = append(d.rejects, fmt.Sprintf("off=%d len=%d", off, len(p)))
		return 0, fmt.Errorf("ERROR_INVALID_PARAMETER")
	}
	if off >= int64(len(d.data)) {
		return 0, io.EOF
	}
	n := copy(p, d.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// bufWriter imita a output.SafeWriter: io.CopyBuffer con buffer de 1 MB.
type bufWriter struct{ got []byte }

func (w *bufWriter) Save(r io.Reader, name string) (*output.WriteResult, error) {
	var b bytes.Buffer
	n, err := io.CopyBuffer(&b, r, make([]byte, 1<<20))
	if err != nil {
		return nil, err
	}
	w.got = b.Bytes()
	return &output.WriteResult{FinalPath: "/mem/" + name, Size: n}, nil
}

// TestCarveOnRawDeviceNeedsAlignment documenta POR QUE existe internal/blockdev.
// Sin el envoltorio, el carver pide los bytes exactos del archivo y la ultima
// lectura queda desalineada: en Windows eso es ERROR_INVALID_PARAMETER y no se
// recupera absolutamente nada de un disco en crudo.
func TestCarveOnRawDeviceNeedsAlignment(t *testing.T) {
	photo := jpeg(300<<10 + 137) // tamano NO multiplo de 512, que es lo normal
	disk := make([]byte, 3*blockSize)
	copy(disk[4096:], photo)

	reg := signatures.NewRegistry()
	if err := reg.Register(signatures.Signature{
		Name: "jpeg", Extension: ".jpg", Category: "image",
		Header: magic.MustParse("FF D8 FF"), Footer: []byte{0xFF, 0xD9},
		MaxSize: 50 << 20,
	}); err != nil {
		t.Fatal(err)
	}

	t.Run("sin envoltorio falla", func(t *testing.T) {
		dev := &strictDevice{data: disk, sector: 512}
		w := &bufWriter{}
		results, _ := New(dev, int64(len(disk)), w, reg).Run()

		if len(dev.rejects) == 0 {
			t.Skip("no hubo lecturas desalineadas; el envoltorio ya no haria falta")
		}
		t.Logf("lecturas rechazadas: %v", dev.rejects)
		if len(results) != 0 {
			t.Errorf("se recuperaron %d archivos pese a los rechazos", len(results))
		}
	})

	t.Run("con envoltorio funciona", func(t *testing.T) {
		dev := &strictDevice{data: disk, sector: 512}
		src := blockdev.NewAligned(dev, 512, int64(len(disk)))
		w := &bufWriter{}

		results, err := New(src, int64(len(disk)), w, reg).Run()
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if len(dev.rejects) != 0 {
			t.Errorf("el dispositivo aun rechazo %d lecturas: %v", len(dev.rejects), dev.rejects)
		}
		if len(results) != 1 {
			t.Fatalf("se recuperaron %d archivos, se esperaba 1", len(results))
		}
		if !bytes.Equal(w.got, photo) {
			t.Errorf("contenido incorrecto: %d bytes de %d", len(w.got), len(photo))
		}
		t.Logf("recuperado intacto: %d bytes, offset %d", results[0].Size, results[0].Offset)
	})
}
