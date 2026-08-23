package filesystem

import (
	"bytes"
	"encoding/binary"
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
		if entry.Recoverable && entry.Offset <= 0 {
			t.Fatalf("entrada marcada como recuperable con offset %d: "+
				"se extraería el sector de arranque como contenido", entry.Offset)
		}
		if entry.Recoverable && entry.Offset+entry.Size > l.size {
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
			if entry.Offset <= 0 || entry.Size <= 0 {
				t.Fatalf("recuperable con offset=%d size=%d", entry.Offset, entry.Size)
			}
			if entry.Offset+entry.Size > l.size {
				t.Fatalf("recuperable fuera del volumen: offset=%d size=%d", entry.Offset, entry.Size)
			}
		}
	})
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
