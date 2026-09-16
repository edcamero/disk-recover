package filesystem

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// newNTFSRecord construye un registro de MFT mínimo con la firma "FILE".
func newNTFSRecord(size int) []byte {
	r := make([]byte, size)
	copy(r[0:4], "FILE")
	binary.LittleEndian.PutUint16(r[4:6], 48)   // offset del USA
	binary.LittleEndian.PutUint16(r[6:8], 1)    // contador del USA
	binary.LittleEndian.PutUint16(r[20:22], 56) // offset del primer atributo
	binary.LittleEndian.PutUint16(r[22:24], 0x01)
	binary.LittleEndian.PutUint32(r[24:28], uint32(size))
	return r
}

// TestParseNTFSRecordHostileOffsets es la regresión directa del panic de [C8].
//
// El offset del primer atributo se lee de data[20:22], es decir, de bytes del
// disco corrupto. La guarda anterior (`offset < len(data)-8`) protegía los
// accesos +4 y +8 pero no los +40, +48, +88 y +90: con offset 1015 sobre un
// buffer de 1024, data[offset+88] es data[1103] y revienta.
func TestParseNTFSRecordHostileOffsets(t *testing.T) {
	p := &ntfsParams{bytesPerSector: 512, clusterSize: 4096, recordSize: 1024}
	l := &Lister{size: 1 << 30}

	// Recorrer TODOS los offsets posibles, incluidos los que disparaban el panic.
	for offset := 0; offset <= 0xFFFF; offset += 7 {
		record := newNTFSRecord(1024)
		binary.LittleEndian.PutUint16(record[20:22], uint16(offset))

		// Rellenar con un patrón que hace que attrType parezca $FILE_NAME.
		for i := 56; i+4 <= len(record); i += 4 {
			binary.LittleEndian.PutUint32(record[i:i+4], attrFileName)
		}

		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic con offset de atributo %d: %v", offset, r)
				}
			}()
			l.parseNTFSRecord(record, p)
		}()
	}
}

// TestParseNTFSRecordNoInfiniteLoop es la regresión de [C8c]: `offset +=
// uint16(attrSize)` truncaba un uint32, así que un attrSize múltiplo de 65536
// daba incremento cero y bucle infinito.
func TestParseNTFSRecordNoInfiniteLoop(t *testing.T) {
	p := &ntfsParams{bytesPerSector: 512, clusterSize: 4096, recordSize: 1024}
	l := &Lister{size: 1 << 30}

	for _, attrSize := range []uint32{0, 1, 8, 0x10000, 0x20000, 0xFFFFFFFF} {
		record := newNTFSRecord(1024)
		binary.LittleEndian.PutUint32(record[56:60], attrFileName)
		binary.LittleEndian.PutUint32(record[60:64], attrSize)

		done := make(chan struct{})
		go func() {
			defer close(done)
			defer func() { recover() }()
			l.parseNTFSRecord(record, p)
		}()

		select {
		case <-done:
		case <-timeoutAfterSeconds(10):
			t.Fatalf("bucle infinito con attrSize = %#x", attrSize)
		}
	}
}

// TestNTFSNeverReportsOffsetZeroAsRecoverable es la regresión de [C8a]. La
// versión anterior nunca asignaba Offset, así que quedaba en 0 y el extractor
// copiaba el sector de arranque como contenido de CADA archivo: N copias del
// boot sector con nombres de fotos, presentadas como una recuperación exitosa.
// Los archivos residentes (Data != nil) sí pueden tener Offset == 0; no son
// el bug que cubre este test.
func TestNTFSNeverReportsOffsetZeroAsRecoverable(t *testing.T) {
	p := &ntfsParams{bytesPerSector: 512, clusterSize: 4096, recordSize: 1024}
	l := &Lister{size: 1 << 30}

	for seed := 0; seed < 500; seed++ {
		record := newNTFSRecord(1024)
		for i := 56; i < len(record); i++ {
			record[i] = byte((i*seed + seed) % 256)
		}

		entry := l.parseNTFSRecord(record, p)
		if entry == nil {
			continue
		}
		if entry.Recoverable && entry.Data == nil && len(entry.Extents) == 0 && entry.Offset <= 0 {
			t.Fatalf("entrada no residente marcada como recuperable con offset %d: "+
				"se extraería el sector de arranque como contenido", entry.Offset)
		}
		if entry.Recoverable && entry.Data == nil && len(entry.Extents) == 0 && entry.Offset+entry.Size > l.size {
			t.Fatalf("entrada recuperable que se sale del volumen: offset=%d size=%d",
				entry.Offset, entry.Size)
		}
	}
}

func TestSignedLE(t *testing.T) {
	tests := []struct {
		in   []byte
		want int64
	}{
		{[]byte{0x01}, 1},
		{[]byte{0xFF}, -1},
		{[]byte{0x00, 0x01}, 256},
		{[]byte{0x00, 0xFF}, -256},
		{[]byte{0x34, 0x12}, 0x1234},
		{[]byte{}, 0},
	}
	for _, tt := range tests {
		if got := signedLE(tt.in); got != tt.want {
			t.Errorf("signedLE(%v) = %d, se esperaba %d", tt.in, got, tt.want)
		}
	}
}

func TestParseRunListRejectsGarbage(t *testing.T) {
	garbage := [][]byte{
		{0xFF, 0xFF, 0xFF}, // tamaños de campo imposibles
		{0x99},             // cabecera que promete bytes que no están
		{0x11},             // truncado
		{0x11, 0x05},       // falta el campo de offset
	}
	for _, g := range garbage {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("parseRunList hizo panic con %v: %v", g, r)
				}
			}()
			parseRunList(g)
		}()
	}
}

// FuzzParseNTFSRecord: el parser de NTFS es el candidato ideal a fuzzing de
// todo el proyecto, porque consume estructuras binarias arbitrarias de un disco
// que por definición está corrupto. No debe hacer panic con ninguna entrada.
func FuzzParseNTFSRecord(f *testing.F) {
	f.Add(newNTFSRecord(1024))
	f.Add(newNTFSRecord(512))
	f.Add([]byte("FILE"))
	f.Add([]byte{})

	// Semilla con un $FILE_NAME plausible.
	seeded := newNTFSRecord(1024)
	binary.LittleEndian.PutUint32(seeded[56:60], attrFileName)
	binary.LittleEndian.PutUint32(seeded[60:64], 104)
	seeded[64] = 0                                   // residente
	binary.LittleEndian.PutUint32(seeded[72:76], 90) // longitud del valor
	binary.LittleEndian.PutUint16(seeded[76:78], 24) // offset del valor
	seeded[56+24+0x40] = 5                           // longitud del nombre
	copy(seeded[56+24+0x42:], []byte{'f', 0, 'o', 0, 't', 0, 'o', 0, '1', 0})
	f.Add(seeded)

	p := &ntfsParams{bytesPerSector: 512, clusterSize: 4096, recordSize: 1024}
	l := &Lister{size: 1 << 30}

	f.Fuzz(func(t *testing.T, data []byte) {
		// No debe entrar en pánico jamás, con ninguna entrada.
		entry := l.parseNTFSRecord(data, p)

		// Y lo que declare recuperable tiene que ser coherente.
		if entry != nil && entry.Recoverable {
			if entry.Data != nil {
				// Residente: el contenido está en memoria, no en disco.
				if entry.Size <= 0 {
					t.Fatalf("residente recuperable con Size=%d", entry.Size)
				}
			} else if len(entry.Extents) > 0 {
				// Fragmentado: cada extent debe caber en el volumen.
				for _, ext := range entry.Extents {
					if ext.Offset <= 0 || ext.Size <= 0 {
						t.Fatalf("extent inválido: offset=%d size=%d", ext.Offset, ext.Size)
					}
					if ext.Offset+ext.Size > l.size {
						t.Fatalf("extent fuera del volumen: offset=%d size=%d", ext.Offset, ext.Size)
					}
				}
			} else {
				if entry.Offset <= 0 || entry.Size <= 0 {
					t.Fatalf("recuperable con offset=%d size=%d", entry.Offset, entry.Size)
				}
				if entry.Offset+entry.Size > l.size {
					t.Fatalf("recuperable fuera del volumen: offset=%d size=%d", entry.Offset, entry.Size)
				}
			}
		}
	})
}

// TestNTFSResidentFileIsExtracted verifica que un archivo cuyo contenido vive
// dentro del registro MFT (residente) se marca como recuperable y el Extractor
// lo escribe correctamente, sin leer del disco de origen.
func TestNTFSResidentFileIsExtracted(t *testing.T) {
	const content = "contenido residente de prueba"
	record := buildResidentMFTRecord(t, "prueba.txt", []byte(content))

	p := &ntfsParams{bytesPerSector: 512, clusterSize: 4096, recordSize: 1024}
	l := &Lister{size: 1 << 30}

	entry := l.parseNTFSRecord(record, p)
	if entry == nil {
		t.Fatal("parseNTFSRecord devolvió nil para un registro residente válido")
	}
	if !entry.Recoverable {
		t.Fatal("entrada residente no marcada como recuperable")
	}
	if entry.Data == nil {
		t.Fatal("Data == nil en una entrada residente")
	}
	if string(entry.Data) != content {
		t.Fatalf("Data = %q, se esperaba %q", entry.Data, content)
	}

	// El Extractor debe escribir el contenido aunque Offset == 0.
	ext := NewExtractor(bytes.NewReader(make([]byte, 1<<20)))
	dest := filepath.Join(t.TempDir(), "salida.txt")
	if _, err := ext.ExtractTo(*entry, dest); err != nil {
		t.Fatalf("ExtractTo residente: %v", err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("no se pudo leer el archivo extraído: %v", err)
	}
	if string(got) != content {
		t.Fatalf("extraído %q, se esperaba %q", got, content)
	}
}

// buildResidentMFTRecord construye un registro MFT mínimo con un $FILE_NAME
// y un $DATA residentes para los tests de recuperación de residentes.
func buildResidentMFTRecord(t *testing.T, name string, content []byte) []byte {
	t.Helper()
	const attrOffset = 56

	nameChars := []uint16{}
	for _, r := range name {
		nameChars = append(nameChars, uint16(r))
	}
	nameBytes := make([]byte, len(nameChars)*2)
	for i, c := range nameChars {
		binary.LittleEndian.PutUint16(nameBytes[i*2:], c)
	}

	// $FILE_NAME residente
	fnValueLen := 66 + len(nameBytes)
	fnAttrLen := 24 + fnValueLen
	if fnAttrLen%8 != 0 {
		fnAttrLen += 8 - fnAttrLen%8
	}
	fnAttr := make([]byte, fnAttrLen)
	binary.LittleEndian.PutUint32(fnAttr[0:4], attrFileName)
	binary.LittleEndian.PutUint32(fnAttr[4:8], uint32(fnAttrLen))
	binary.LittleEndian.PutUint16(fnAttr[10:12], 24) // name offset
	binary.LittleEndian.PutUint32(fnAttr[16:20], uint32(fnValueLen))
	binary.LittleEndian.PutUint16(fnAttr[20:22], 24) // value offset
	fnAttr[24+0x40] = byte(len(nameChars))
	fnAttr[24+0x41] = 1 // espacio Win32
	copy(fnAttr[24+0x42:], nameBytes)

	// $DATA residente
	dataAttrLen := 24 + len(content)
	if dataAttrLen%8 != 0 {
		dataAttrLen += 8 - dataAttrLen%8
	}
	dataAttr := make([]byte, dataAttrLen)
	binary.LittleEndian.PutUint32(dataAttr[0:4], attrData)
	binary.LittleEndian.PutUint32(dataAttr[4:8], uint32(dataAttrLen))
	binary.LittleEndian.PutUint16(dataAttr[10:12], 24) // name offset
	binary.LittleEndian.PutUint32(dataAttr[16:20], uint32(len(content)))
	binary.LittleEndian.PutUint16(dataAttr[20:22], 24) // value offset
	copy(dataAttr[24:], content)

	// Marcador de fin
	end := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00}

	used := attrOffset + len(fnAttr) + len(dataAttr) + len(end)
	rec := newNTFSRecord(max(1024, used+8))
	binary.LittleEndian.PutUint16(rec[22:24], 0x01) // archivo activo
	binary.LittleEndian.PutUint32(rec[24:28], uint32(used))

	pos := attrOffset
	copy(rec[pos:], fnAttr)
	pos += len(fnAttr)
	copy(rec[pos:], dataAttr)
	pos += len(dataAttr)
	copy(rec[pos:], end)

	return rec
}

// TestNTFSFragmentedFileIsExtracted verifica que un archivo cuyo $DATA ocupa
// varios data runs se marca como recuperable y el Extractor concatena los
// fragmentos en orden.
func TestNTFSFragmentedFileIsExtracted(t *testing.T) {
	const clusterSize = 4096
	const lcn1, runLen1 int64 = 10, 2 // disco: [40960 .. 49152)
	const lcn2, runLen2 int64 = 20, 3 // disco: [81920 .. 94208)
	realSize := (runLen1 + runLen2) * clusterSize

	record := buildFragmentedMFTRecord(t, "frag.txt", lcn1, runLen1, lcn2, runLen2, realSize)

	p := &ntfsParams{bytesPerSector: 512, clusterSize: clusterSize, recordSize: 1024}
	volumeSize := int64(1 << 20) // 1 MB — suficiente para LCN=20
	l := &Lister{size: volumeSize}

	entry := l.parseNTFSRecord(record, p)
	if entry == nil {
		t.Fatal("parseNTFSRecord devolvió nil")
	}
	if !entry.Recoverable {
		t.Fatal("fragmentado no marcado como recuperable")
	}
	if len(entry.Extents) != 2 {
		t.Fatalf("extents=%d, se esperaban 2", len(entry.Extents))
	}
	if entry.Extents[0] != (Extent{Offset: lcn1 * clusterSize, Size: runLen1 * clusterSize}) {
		t.Fatalf("extent[0]=%+v", entry.Extents[0])
	}
	if entry.Extents[1] != (Extent{Offset: lcn2 * clusterSize, Size: runLen2 * clusterSize}) {
		t.Fatalf("extent[1]=%+v", entry.Extents[1])
	}

	// Poner datos conocidos en cada fragmento y verificar la extracción.
	disk := make([]byte, volumeSize)
	seg1 := bytes.Repeat([]byte{0xAA}, int(runLen1*clusterSize))
	seg2 := bytes.Repeat([]byte{0xBB}, int(runLen2*clusterSize))
	copy(disk[lcn1*clusterSize:], seg1)
	copy(disk[lcn2*clusterSize:], seg2)

	ext := NewExtractor(bytes.NewReader(disk))
	dest := filepath.Join(t.TempDir(), "frag_out.bin")
	res, err := ext.ExtractTo(*entry, dest)
	if err != nil {
		t.Fatalf("ExtractTo: %v", err)
	}
	if res.Written != realSize {
		t.Fatalf("written=%d, se esperaba %d", res.Written, realSize)
	}
	got, readErr := os.ReadFile(dest)
	if readErr != nil {
		t.Fatal(readErr)
	}
	want := append(seg1, seg2...)
	if !bytes.Equal(got, want) {
		t.Fatalf("contenido extraído no coincide: got[0]=%#x want[0]=%#x", got[0], want[0])
	}
}

// buildFragmentedMFTRecord construye un registro MFT con $FILE_NAME residente
// y $DATA no residente con dos data runs, para los tests de NTFS fragmentado.
func buildFragmentedMFTRecord(t *testing.T, name string, lcn1, runLen1, lcn2, runLen2, realSize int64) []byte {
	t.Helper()
	const attrOffset = 56

	nameChars := []uint16{}
	for _, r := range name {
		nameChars = append(nameChars, uint16(r))
	}
	nameBytes := make([]byte, len(nameChars)*2)
	for i, c := range nameChars {
		binary.LittleEndian.PutUint16(nameBytes[i*2:], c)
	}

	fnValueLen := 66 + len(nameBytes)
	fnAttrLen := 24 + fnValueLen
	if fnAttrLen%8 != 0 {
		fnAttrLen += 8 - fnAttrLen%8
	}
	fnAttr := make([]byte, fnAttrLen)
	binary.LittleEndian.PutUint32(fnAttr[0:4], attrFileName)
	binary.LittleEndian.PutUint32(fnAttr[4:8], uint32(fnAttrLen))
	binary.LittleEndian.PutUint16(fnAttr[10:12], 24)
	binary.LittleEndian.PutUint32(fnAttr[16:20], uint32(fnValueLen))
	binary.LittleEndian.PutUint16(fnAttr[20:22], 24)
	fnAttr[24+0x40] = byte(len(nameChars))
	fnAttr[24+0x41] = 1
	copy(fnAttr[24+0x42:], nameBytes)

	// Run list: dos fragmentos (lenSize=1, offSize=1) + terminador.
	// El segundo LCN se codifica como delta (lcn2 - lcn1).
	delta := lcn2 - lcn1
	runList := []byte{
		0x11, byte(runLen1), byte(lcn1),
		0x11, byte(runLen2), byte(delta),
		0x00,
	}

	// $DATA no residente: cabecera de 0x40 bytes, run list inmediatamente después.
	dataAttrLen := 0x40 + len(runList)
	if dataAttrLen%8 != 0 {
		dataAttrLen += 8 - dataAttrLen%8
	}
	dataAttr := make([]byte, dataAttrLen)
	binary.LittleEndian.PutUint32(dataAttr[0:4], attrData)
	binary.LittleEndian.PutUint32(dataAttr[4:8], uint32(dataAttrLen))
	dataAttr[8] = 1 // no residente
	binary.LittleEndian.PutUint16(dataAttr[0x20:0x22], 0x40) // mapping pairs offset
	binary.LittleEndian.PutUint64(dataAttr[0x30:0x38], uint64(realSize))
	copy(dataAttr[0x40:], runList)

	end := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00}

	used := attrOffset + len(fnAttr) + len(dataAttr) + len(end)
	rec := newNTFSRecord(max(1024, used+8))
	binary.LittleEndian.PutUint16(rec[22:24], 0x01)
	binary.LittleEndian.PutUint32(rec[24:28], uint32(used))

	pos := attrOffset
	copy(rec[pos:], fnAttr)
	pos += len(fnAttr)
	copy(rec[pos:], dataAttr)
	pos += len(dataAttr)
	copy(rec[pos:], end)

	return rec
}

// FuzzDetectFilesystem: la detección lee bytes arbitrarios del inicio del disco.
func FuzzDetectFilesystem(f *testing.F) {
	f.Add(make([]byte, 4096))
	f.Add([]byte{0x55, 0xAA})
	f.Add([]byte("NTFS    "))

	f.Fuzz(func(t *testing.T, data []byte) {
		l := NewLister(bytes.NewReader(data), int64(len(data)))
		_ = l.FSType() // no debe hacer panic
	})
}
