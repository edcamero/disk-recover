package scanner

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

var errBadSector = errors.New("sector defectuoso simulado")

// faultyReader simula un dispositivo de bloque con una región ilegible, que es
// el comportamiento real de un disco dañado: lectura corta más error.
type faultyReader struct {
	data     []byte
	badStart int64
	badEnd   int64
	reads    int
}

func (r *faultyReader) ReadAt(p []byte, off int64) (int, error) {
	r.reads++

	if off < 0 || off >= int64(len(r.data)) {
		return 0, io.EOF
	}

	// El propio inicio cae en la región mala: no se lee nada.
	if off >= r.badStart && off < r.badEnd {
		return 0, errBadSector
	}

	end := off + int64(len(p))
	if end > int64(len(r.data)) {
		end = int64(len(r.data))
	}

	// La lectura alcanza la región mala: se corta ahí.
	truncated := false
	if off < r.badStart && end > r.badStart {
		end = r.badStart
		truncated = true
	}

	n := copy(p, r.data[off:end])
	switch {
	case truncated:
		return n, errBadSector
	case off+int64(n) >= int64(len(r.data)):
		return n, io.EOF
	}
	return n, nil
}

// coverage registra qué bytes del origen llegaron al callback.
func coverage(t *testing.T, s *Scanner, size int64) []bool {
	t.Helper()
	seen := make([]bool, size)
	err := s.Scan(func(offset int64, data []byte) error {
		for i := range data {
			if idx := offset + int64(i); idx < size {
				seen[idx] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Scan() devolvió error: %v", err)
	}
	return seen
}

func TestScanCoversEveryByte(t *testing.T) {
	const size = 10000
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i)
	}

	s := NewScanner(bytes.NewReader(data), size, Config{BlockSize: 1024, Overlap: 128})
	seen := coverage(t, s, size)

	for i, ok := range seen {
		if !ok {
			t.Fatalf("el byte %d no se escaneó nunca", i)
		}
	}
}

// TestScanOverlap comprueba que la zona de solape se entrega DOS veces. Es el
// mecanismo que permite encontrar una firma a caballo entre dos bloques.
func TestScanOverlap(t *testing.T) {
	const (
		size      = 4096
		blockSize = 1024
		overlap   = 256
	)
	data := make([]byte, size)

	counts := make([]int, size)
	s := NewScanner(bytes.NewReader(data), size, Config{BlockSize: blockSize, Overlap: overlap})
	err := s.Scan(func(offset int64, d []byte) error {
		for i := range d {
			counts[offset+int64(i)]++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Scan() devolvió error: %v", err)
	}

	// Los bytes justo después del primer bloque están en la zona de solape.
	for i := blockSize; i < blockSize+overlap; i++ {
		if counts[i] < 2 {
			t.Errorf("el byte %d se procesó %d vez/veces, se esperaban 2 (solape)", i, counts[i])
		}
	}
	// Un byte en mitad del primer bloque solo debe verse una vez.
	if counts[blockSize/2] != 1 {
		t.Errorf("el byte %d se procesó %d veces, se esperaba 1", blockSize/2, counts[blockSize/2])
	}
}

// TestScanShortReadDoesNotSkipData es la regresión de [I1]: con un sector
// defectuoso, la versión anterior avanzaba BlockSize sin mirar cuántos bytes
// había leído de verdad, y los bytes entre el final de la lectura y el final
// del bloque no se escaneaban jamás.
func TestScanShortReadDoesNotSkipData(t *testing.T) {
	const (
		size      = 8192
		blockSize = 1024
		overlap   = 128
		badStart  = 1500
		badEnd    = 2048
	)
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i % 251)
	}

	src := &faultyReader{data: data, badStart: badStart, badEnd: badEnd}
	s := NewScanner(src, size, Config{BlockSize: blockSize, Overlap: overlap, SectorSize: 512})
	seen := coverage(t, s, size)

	// Todo lo legible tiene que haberse escaneado.
	for i := 0; i < size; i++ {
		if i >= badStart && i < badEnd {
			continue // región ilegible, es correcto no verla
		}
		if !seen[i] {
			t.Fatalf("el byte legible %d se saltó (región mala: [%d,%d))", i, badStart, badEnd)
		}
	}

	// Y el escáner tiene que haber informado de la región perdida.
	regions := s.Unreadable()
	if len(regions) == 0 {
		t.Fatal("se esperaba al menos una región ilegible reportada, no hubo ninguna")
	}
}

// TestScanZeroSizeReturnsError: antes esto producía un error con "%!w(<nil>)".
func TestScanZeroSize(t *testing.T) {
	s := NewScanner(bytes.NewReader(nil), 0, Config{})
	err := s.Scan(func(int64, []byte) error { return nil })
	if err == nil {
		t.Fatal("se esperaba error con tamaño 0")
	}
	if bytes.Contains([]byte(err.Error()), []byte("%!w")) {
		t.Errorf("error mal formateado: %q", err)
	}
}

func TestScanCancel(t *testing.T) {
	const size = 1 << 20
	data := make([]byte, size)

	cancel := make(chan struct{})
	close(cancel) // cancelado desde el principio

	s := NewScanner(bytes.NewReader(data), size, Config{BlockSize: 1024, Overlap: 128})
	s.SetCancelChannel(cancel)

	calls := 0
	err := s.Scan(func(int64, []byte) error {
		calls++
		return nil
	})

	if err == nil {
		t.Fatal("se esperaba error de cancelación")
	}
	if calls != 0 {
		t.Errorf("el callback se llamó %d veces pese a estar cancelado", calls)
	}
}

// TestScanCallbackErrorStops verifica que el callback puede abortar el escaneo.
func TestScanCallbackErrorStops(t *testing.T) {
	data := make([]byte, 8192)
	want := errors.New("parar")

	s := NewScanner(bytes.NewReader(data), int64(len(data)), Config{BlockSize: 1024, Overlap: 128})
	err := s.Scan(func(int64, []byte) error { return want })

	if !errors.Is(err, want) {
		t.Fatalf("Scan() = %v, se esperaba %v", err, want)
	}
}

// TestScanTerminates es la red de seguridad contra bucles infinitos: pase lo
// que pase con las lecturas, Scan debe terminar.
func TestScanTerminates(t *testing.T) {
	sizes := []int64{1, 511, 512, 513, 1023, 1024, 1025, 4096, 10000}
	for _, size := range sizes {
		data := make([]byte, size)
		s := NewScanner(bytes.NewReader(data), size, Config{BlockSize: 512, Overlap: 128})

		iterations := 0
		err := s.Scan(func(int64, []byte) error {
			iterations++
			if iterations > 1000 {
				return errors.New("demasiadas iteraciones: probable bucle infinito")
			}
			return nil
		})
		if err != nil {
			t.Fatalf("tamaño %d: %v", size, err)
		}
	}
}

// TestNewScannerClampsOverlap: un overlap >= BlockSize daría avance cero.
func TestNewScannerClampsOverlap(t *testing.T) {
	s := NewScanner(bytes.NewReader(nil), 100, Config{BlockSize: 1024, Overlap: 4096})
	if s.config.Overlap >= s.config.BlockSize {
		t.Errorf("overlap %d no se recortó por debajo de BlockSize %d",
			s.config.Overlap, s.config.BlockSize)
	}
}
