package filesystem

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"
)

// =========================================================================
// Constructor de imágenes FAT32 sintéticas
// =========================================================================

const (
	testBytesPerSector    = 512
	testSectorsPerCluster = 1
	testReservedSectors   = 32
	testNumFATs           = 1
)

type fat32Image struct {
	data        []byte
	clusterSize int64
	fatStart    int64
	dataStart   int64
}

// newFAT32Image construye en memoria un volumen FAT32 mínimo pero válido.
// Poder fabricar sistemas de archivos sintéticos es lo que permite testear este
// paquete sin un disco real: todo consume io.ReaderAt.
func newFAT32Image(clusters int) *fat32Image {
	clusterSize := int64(testBytesPerSector * testSectorsPerCluster)
	sectorsPerFAT := int64((clusters+2)*4/testBytesPerSector + 1)
	fatStart := int64(testReservedSectors * testBytesPerSector)
	fatBytes := sectorsPerFAT * testBytesPerSector
	dataStart := fatStart + testNumFATs*fatBytes
	total := dataStart + int64(clusters+2)*clusterSize

	img := &fat32Image{
		data:        make([]byte, total),
		clusterSize: clusterSize,
		fatStart:    fatStart,
		dataStart:   dataStart,
	}

	boot := img.data[:512]
	binary.LittleEndian.PutUint16(boot[11:13], testBytesPerSector)
	boot[13] = testSectorsPerCluster
	binary.LittleEndian.PutUint16(boot[14:16], testReservedSectors)
	boot[16] = testNumFATs
	binary.LittleEndian.PutUint32(boot[36:40], uint32(sectorsPerFAT))
	binary.LittleEndian.PutUint32(boot[44:48], 2) // cluster raíz
	copy(boot[82:87], "FAT32")
	boot[510], boot[511] = 0x55, 0xAA

	// Toda cadena termina en su primer cluster salvo que el test diga otra cosa.
	for c := 2; c < clusters+2; c++ {
		img.setFATEntry(uint32(c), 0x0FFFFFFF)
	}

	return img
}

func (i *fat32Image) setFATEntry(cluster, value uint32) {
	off := i.fatStart + int64(cluster)*4
	if off+4 <= int64(len(i.data)) {
		binary.LittleEndian.PutUint32(i.data[off:off+4], value)
	}
}

func (i *fat32Image) clusterOffset(cluster uint32) int64 {
	return i.dataStart + int64(cluster-2)*i.clusterSize
}

// writeDirEntries vuelca entradas de directorio en un cluster.
func (i *fat32Image) writeDirEntries(cluster uint32, entries ...[]byte) {
	off := i.clusterOffset(cluster)
	for _, e := range entries {
		if off+int64(len(e)) > int64(len(i.data)) {
			return
		}
		copy(i.data[off:], e)
		off += int64(len(e))
	}
}

func (i *fat32Image) size() int64 { return int64(len(i.data)) }

// shortEntry crea una entrada de directorio 8.3.
func shortEntry(name, ext string, attr byte, cluster uint32, size uint32) []byte {
	e := make([]byte, 32)
	copy(e[0:8], strings.ToUpper(name)+strings.Repeat(" ", 8))
	copy(e[8:11], strings.ToUpper(ext)+strings.Repeat(" ", 3))
	e[11] = attr
	binary.LittleEndian.PutUint16(e[20:22], uint16(cluster>>16))
	binary.LittleEndian.PutUint16(e[26:28], uint16(cluster))
	binary.LittleEndian.PutUint32(e[28:32], size)
	// Fecha válida: 15 de junio de 2024.
	binary.LittleEndian.PutUint16(e[24:26], uint16((2024-1980)<<9|6<<5|15))
	return e
}

// lfnEntry crea una entrada de nombre largo con el número de secuencia dado.
func lfnEntry(seq byte, last bool, chars string) []byte {
	e := make([]byte, 32)
	e[0] = seq
	if last {
		e[0] |= 0x40
	}
	e[11] = 0x0F // atributo de nombre largo

	units := utf16.Encode([]rune(chars))
	for len(units) < 13 {
		units = append(units, 0xFFFF)
	}

	put := func(start int, from, count int) {
		for k := 0; k < count; k++ {
			binary.LittleEndian.PutUint16(e[start+k*2:start+k*2+2], units[from+k])
		}
	}
	put(1, 0, 5)
	put(14, 5, 6)
	put(28, 11, 2)
	return e
}

// =========================================================================
// Detección
// =========================================================================

func TestDetectFAT32(t *testing.T) {
	img := newFAT32Image(8)
	l := NewLister(bytes.NewReader(img.data), img.size())
	if got := l.FSType(); got != "fat32" {
		t.Errorf("FSType() = %q, se esperaba %q", got, "fat32")
	}
}

// TestDetectNTFS es la regresión de [I3]. La comprobación era
// string(buf[3:7]) == "NTFS    ", que compara 4 bytes con una cadena de 8: la
// condición era constante-falsa y NTFS no se detectaba NUNCA.
func TestDetectNTFS(t *testing.T) {
	data := make([]byte, 4096)
	copy(data[3:11], "NTFS    ")
	binary.LittleEndian.PutUint16(data[11:13], 512)
	data[13] = 8

	l := NewLister(bytes.NewReader(data), int64(len(data)))
	if got := l.FSType(); got != "ntfs" {
		t.Errorf("FSType() = %q, se esperaba %q", got, "ntfs")
	}
}

// TestDetectExt4 es la otra mitad de [I3]: el superbloque está en el offset
// 1024, pero el buffer medía 1024 bytes y la comprobación iba tras un
// `len(buf) > 1082` imposible de cumplir.
func TestDetectExt4(t *testing.T) {
	data := make([]byte, 4096)
	data[1080], data[1081] = 0x53, 0xEF // 0xEF53 little-endian

	l := NewLister(bytes.NewReader(data), int64(len(data)))
	if got := l.FSType(); got != "ext4" {
		t.Errorf("FSType() = %q, se esperaba %q", got, "ext4")
	}
}

// TestDetectFAT16NotTreatedAsFAT32 es la regresión de [I4]: FAT16 se devolvía
// como "fat32", y listFAT32 leía BPB_RootClus del offset 44, campo que en FAT16
// ni siquiera existe.
func TestDetectFAT16NotTreatedAsFAT32(t *testing.T) {
	data := make([]byte, 4096)
	copy(data[54:58], "FAT1")
	data[510], data[511] = 0x55, 0xAA

	l := NewLister(bytes.NewReader(data), int64(len(data)))
	if got := l.FSType(); got == "fat32" {
		t.Error("un volumen FAT16 se está tratando como FAT32")
	}
}

// =========================================================================
// Validación del BPB
// =========================================================================

// TestBPBValidation es la regresión de [I6]. Sin validar, un bytesPerSector de
// 0 propagaba un clusterSize de 0 y el recorrido producía basura en silencio,
// sin un solo error.
func TestBPBValidation(t *testing.T) {
	tests := []struct {
		name   string
		break_ func(boot []byte)
	}{
		{"bytesPerSector cero", func(b []byte) { binary.LittleEndian.PutUint16(b[11:13], 0) }},
		{"bytesPerSector no potencia de 2", func(b []byte) { binary.LittleEndian.PutUint16(b[11:13], 777) }},
		{"sectorsPerCluster cero", func(b []byte) { b[13] = 0 }},
		{"sectorsPerCluster no potencia de 2", func(b []byte) { b[13] = 7 }},
		{"numFATs cero", func(b []byte) { b[16] = 0 }},
		{"sectoresReservados cero", func(b []byte) { binary.LittleEndian.PutUint16(b[14:16], 0) }},
		{"sectorsPerFAT cero", func(b []byte) { binary.LittleEndian.PutUint32(b[36:40], 0) }},
		{"rootCluster inválido", func(b []byte) { binary.LittleEndian.PutUint32(b[44:48], 1) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			img := newFAT32Image(8)
			tt.break_(img.data[:512])

			l := NewLister(bytes.NewReader(img.data), img.size())
			if _, err := l.listFAT32(); err == nil {
				t.Error("se esperaba un error explícito, se aceptó el BPB corrupto")
			}
		})
	}
}

// =========================================================================
// El crash de [C7]
// =========================================================================

// TestWalkFAT32CyclicDirsTerminates es la regresión del crítico [C7]. En una
// FAT corrupta es trivial que el directorio A apunte al B y el B de vuelta al
// A. Sin conjunto de visitados, walkFAT32Dir recursaba sin fin hasta desbordar
// la pila, un panic no recuperable que se lleva por delante todo el trabajo ya
// hecho.
//
// Si esta prueba se cuelga o revienta, la regresión ha vuelto.
func TestWalkFAT32CyclicDirsTerminates(t *testing.T) {
	img := newFAT32Image(16)

	// Raíz (cluster 2) -> SUBDIR (cluster 3)
	img.writeDirEntries(2,
		shortEntry("SUBDIR", "", attrDirectory, 3, 0),
		shortEntry("FOTO", "JPG", 0x20, 4, 1024),
	)
	// SUBDIR (cluster 3) -> OTRO (cluster 4)... que vuelve a la raíz.
	img.writeDirEntries(3,
		shortEntry("OTRO", "", attrDirectory, 4, 0),
	)
	// El ciclo se cierra: cluster 4 apunta de vuelta al 2.
	img.writeDirEntries(4,
		shortEntry("VUELTA", "", attrDirectory, 2, 0),
	)

	l := NewLister(bytes.NewReader(img.data), img.size())

	done := make(chan []FileEntry, 1)
	go func() {
		entries, _ := l.listFAT32()
		done <- entries
	}()

	select {
	case entries := <-done:
		t.Logf("terminó correctamente con %d entradas", len(entries))
	case <-timeoutAfterSeconds(15):
		t.Fatal("listFAT32 no terminó: recursión infinita por directorios cíclicos")
	}
}

// TestSelfReferencingDirTerminates: el caso mínimo, un directorio que se apunta
// a sí mismo.
func TestSelfReferencingDirTerminates(t *testing.T) {
	img := newFAT32Image(8)
	img.writeDirEntries(2, shortEntry("YO", "", attrDirectory, 2, 0))

	l := NewLister(bytes.NewReader(img.data), img.size())

	done := make(chan struct{})
	go func() {
		l.listFAT32()
		close(done)
	}()

	select {
	case <-done:
	case <-timeoutAfterSeconds(15):
		t.Fatal("un directorio autorreferente provocó recursión infinita")
	}
}

// TestClusterChainCycleTerminates: el ciclo dentro de una sola cadena de
// clusters, distinto del ciclo entre directorios.
func TestClusterChainCycleTerminates(t *testing.T) {
	img := newFAT32Image(8)
	// La cadena 2 -> 3 -> 2 nunca llega a un marcador de fin.
	img.setFATEntry(2, 3)
	img.setFATEntry(3, 2)
	img.writeDirEntries(2, shortEntry("A", "TXT", 0x20, 4, 10))

	l := NewLister(bytes.NewReader(img.data), img.size())

	done := make(chan struct{})
	go func() {
		l.listFAT32()
		close(done)
	}()

	select {
	case <-done:
	case <-timeoutAfterSeconds(15):
		t.Fatal("un ciclo en la cadena de clusters no terminó")
	}
}

// =========================================================================
// Nombres
// =========================================================================

// TestFAT32LongFileNames es la regresión de [I9]. El código anterior tenía un
// comentario diciendo "las acumulamos para la siguiente entrada corta" seguido
// de un `continue` que no acumulaba nada, así que solo sobrevivían los nombres
// 8.3 mutilados. Como el argumento de venta del proyecto es "recupera nombres
// originales", eso invalidaba la propuesta de valor entera en FAT32.
func TestFAT32LongFileNames(t *testing.T) {
	img := newFAT32Image(8)

	// "Vacaciones2024.jpg" ocupa dos entradas LFN de 13 caracteres.
	img.writeDirEntries(2,
		lfnEntry(2, true, "24.jpg"),
		lfnEntry(1, false, "Vacaciones20"),
		shortEntry("VACACI~1", "JPG", 0x20, 3, 2048),
	)

	l := NewLister(bytes.NewReader(img.data), img.size())
	entries, err := l.listFAT32()
	if err != nil {
		t.Fatalf("listFAT32: %v", err)
	}

	for _, e := range entries {
		if strings.Contains(e.Name, "~") {
			t.Errorf("se devolvió el nombre corto mutilado %q en lugar del largo", e.Name)
		}
		if strings.EqualFold(e.Name, "Vacaciones2024.jpg") {
			return // reensamblado correctamente
		}
	}

	var got []string
	for _, e := range entries {
		got = append(got, e.Name)
	}
	t.Errorf("no se reensambló el nombre largo; se obtuvo %v", got)
}

// TestFAT32InvalidClusterSkipped es la regresión de [M11]: firstCluster es
// uint32, así que con valor 0 o 1 la resta firstCluster-2 hace underflow a
// ~4.29e9 y produce un offset astronómico. El código anterior calculaba el
// offset ANTES de comprobar y dejaba esa basura dentro del FileEntry.
func TestFAT32InvalidClusterSkipped(t *testing.T) {
	img := newFAT32Image(8)
	img.writeDirEntries(2,
		shortEntry("MALO", "JPG", 0x20, 0, 1024),  // cluster 0
		shortEntry("MALO2", "JPG", 0x20, 1, 1024), // cluster 1
	)

	l := NewLister(bytes.NewReader(img.data), img.size())
	entries, _ := l.listFAT32()

	for _, e := range entries {
		if e.Offset < 0 || e.Offset >= img.size() {
			t.Errorf("la entrada %q tiene un offset fuera del volumen: %d (tamaño %d)",
				e.Name, e.Offset, img.size())
		}
	}
}

func TestDecodeFATTimeRejectsImpossibleDates(t *testing.T) {
	// Mes 15, día 40: datos corruptos. time.Date los normalizaría a una fecha
	// plausible pero falsa, así que se devuelve el cero.
	got := decodeFATTime(0, uint16(44<<9|15<<5|40))
	if !got.IsZero() {
		t.Errorf("decodeFATTime aceptó una fecha imposible: %v", got)
	}
}
