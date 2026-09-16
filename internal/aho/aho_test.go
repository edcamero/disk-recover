package aho

import (
	"testing"

	"github.com/edcamero/disk-recover/internal/signatures"
	"github.com/edcamero/disk-recover/pkg/magic"
)

func TestNewAutomaton(t *testing.T) {
	sigs := []signatures.Signature{
		{Name: "jpeg", Header: magic.MustParse("FF D8 FF")},
		{Name: "png", Header: magic.MustParse("89 50 4E 47")},
		{Name: "gif", Header: magic.MustParse("47 49 46 38")},
	}

	a := NewAutomaton(sigs)
	if a == nil {
		t.Fatal("NewAutomaton devolvió nil con firmas válidas")
	}
	if len(a.sigs) != 3 {
		t.Errorf("Esperadas 3 firmas, got %d", len(a.sigs))
	}
}

func TestAutomatonFindAll(t *testing.T) {
	sigs := []signatures.Signature{
		{Name: "jpeg", Header: magic.MustParse("FF D8 FF")},
		{Name: "png", Header: magic.MustParse("89 50 4E 47")},
	}

	a := NewAutomaton(sigs)

	tests := []struct {
		name     string
		data     []byte
		wantLen  int
		wantSigs []int
	}{
		{
			name:     "single jpeg",
			data:     []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00},
			wantLen:  1,
			wantSigs: []int{0},
		},
		{
			name:     "single png",
			data:     []byte{0x89, 0x50, 0x4E, 0x47, 0x0D},
			wantLen:  1,
			wantSigs: []int{1},
		},
		{
			name:     "multiple signatures",
			data:     append([]byte{0xFF, 0xD8, 0xFF, 0xE0}, []byte{0x89, 0x50, 0x4E, 0x47, 0x0D}...),
			wantLen:  2,
			wantSigs: []int{0, 1},
		},
		{
			name:    "no match",
			data:    []byte{0x00, 0x00, 0x00, 0x00},
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := a.FindAll(tt.data)
			if len(matches) != tt.wantLen {
				t.Errorf("FindAll() len = %d, want %d", len(matches), tt.wantLen)
			}
			for i, m := range matches {
				if i < len(tt.wantSigs) && m.SigIdx != tt.wantSigs[i] {
					t.Errorf("match[%d].SigIdx = %d, want %d", i, m.SigIdx, tt.wantSigs[i])
				}
			}
		})
	}
}

func TestAutomatonWithWildcards(t *testing.T) {
	// MP4 con wildcards: "?? ?? ?? ?? 66 74 79 70"
	sigs := []signatures.Signature{
		{Name: "mp4", Header: magic.MustParse("?? ?? ?? ?? 66 74 79 70")},
	}

	a := NewAutomaton(sigs)
	if a == nil {
		t.Fatal("NewAutomaton devolvió nil con wildcard")
	}

	// Datos con "ftyp" en offset 4. El patrón completo empieza en 0.
	data := []byte{0x00, 0x00, 0x00, 0x00, 'f', 't', 'y', 'p'}
	matches := a.FindAll(data)

	if len(matches) != 1 {
		t.Fatalf("FindAll() encontró %d coincidencias, esperado 1", len(matches))
	}
	// El autómata ahora corrige el offset: encuentra "ftyp" en 4, pero el
	// patrón completo (con los 4 bytes wildcard antes) empieza en 0.
	if matches[0].Offset != 0 {
		t.Errorf("Offset = %d, want 0 (inicio del patrón completo)", matches[0].Offset)
	}
}

func TestAutomatonEmptyInput(t *testing.T) {
	sigs := []signatures.Signature{
		{Name: "jpeg", Header: magic.MustParse("FF D8 FF")},
	}
	a := NewAutomaton(sigs)

	if matches := a.FindAll([]byte{}); len(matches) != 0 {
		t.Errorf("FindAll(empty) = %d matches, want 0", len(matches))
	}
	if matches := a.FindAll(nil); len(matches) != 0 {
		t.Errorf("FindAll(nil) = %d matches, want 0", len(matches))
	}
}

func TestAutomatonNoSignatures(t *testing.T) {
	a := NewAutomaton([]signatures.Signature{})
	if a != nil {
		t.Error("NewAutomaton con 0 firmas debería devolver nil")
	}
}

// Benchmark comparando búsqueda secuencial vs Aho-Corasick.
func BenchmarkSequentialSearch(b *testing.B) {
	sigs := signatures.DefaultSignatures
	data := make([]byte, 1<<20) // 1 MB

	// Llenar con datos pseudo-aleatorios
	for i := range data {
		data[i] = byte(i % 256)
	}
	// Insertar algunas coincidencias
	copy(data[100:], []byte{0xFF, 0xD8, 0xFF})          // JPEG
	copy(data[500000:], []byte{0x89, 0x50, 0x4E, 0x47}) // PNG

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		count := 0
		for _, sig := range sigs {
			start := 0
			for start < len(data) {
				idx := sig.Header.Find(data[start:])
				if idx < 0 {
					break
				}
				count++
				start += idx + 1
			}
		}
		_ = count
	}
}

func BenchmarkAhoCorasick(b *testing.B) {
	sigs := signatures.DefaultSignatures
	a := NewAutomaton(sigs)
	data := make([]byte, 1<<20) // 1 MB

	// Llenar con datos pseudo-aleatorios
	for i := range data {
		data[i] = byte(i % 256)
	}
	// Insertar algunas coincidencias
	copy(data[100:], []byte{0xFF, 0xD8, 0xFF})          // JPEG
	copy(data[500000:], []byte{0x89, 0x50, 0x4E, 0x47}) // PNG

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matches := a.FindAll(data)
		_ = matches
	}
}
