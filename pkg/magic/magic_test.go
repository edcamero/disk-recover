package magic

import (
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		input   string
		wantHex string
		wantErr bool
	}{
		{"FFD8FF", "FF D8 FF", false},
		{"ff d8 ff", "FF D8 FF", false},
		{"FF D8 FF", "FF D8 FF", false},
		{"FF ?? FF", "FF ?? FF", false},
		{"", "", true},
		{"GG", "", true}, // hex inválido
	}

	for _, tt := range tests {
		m, err := Parse(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("Parse(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if err == nil && m.Hex() != tt.wantHex {
			t.Errorf("Parse(%q).Hex() = %q, want %q", tt.input, m.Hex(), tt.wantHex)
		}
	}
}

func TestMatch(t *testing.T) {
	jpeg := MustParse("FF D8 FF")
	data := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00}

	if !jpeg.Match(data) {
		t.Error("debería coincidir con JPEG")
	}

	png := MustParse("89 50 4E 47")
	if png.Match(data) {
		t.Error("no debería coincidir con PNG")
	}
}

func TestWildcard(t *testing.T) {
	// MP4: los primeros 4 bytes son tamaño (variable), luego "ftyp"
	mp4 := MustParse("?? ?? ?? ?? 66 74 79 70")
	data := []byte{0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70}

	if !mp4.Match(data) {
		t.Error("wildcard debería coincidir con MP4")
	}
}

func TestFind(t *testing.T) {
	m := MustParse("FF D8")
	data := []byte{0x00, 0x00, 0xFF, 0xD8, 0xFF, 0xE0}

	idx := m.Find(data)
	if idx != 2 {
		t.Errorf("Find() = %d, want 2", idx)
	}

	idx = m.Find([]byte{0x00, 0x00})
	if idx != -1 {
		t.Errorf("Find() en datos sin coincidencia = %d, want -1", idx)
	}
}

func TestDetect(t *testing.T) {
	tests := []struct {
		data []byte
		want string
	}{
		{[]byte{0xFF, 0xD8, 0xFF, 0xE0}, "jpeg"},
		{[]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, "png"},
		{[]byte{0x25, 0x50, 0x44, 0x46, 0x2D}, "pdf"},
		{[]byte{0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70}, "mp4"},
		{[]byte{0x00, 0x00, 0x00}, "unknown"},
	}

	for _, tt := range tests {
		got := DetectString(tt.data)
		if got != tt.want {
			t.Errorf("DetectString(%v) = %q, want %q", tt.data, got, tt.want)
		}
	}
}

// TestEqual es la regresión de [I13]. La versión anterior comparaba bytes
// enmascarados (b & mask): un byte literal 0x00 da 0, y un comodín también da
// 0, así que New([]byte{0x00}) resultaba igual a MustParse("??"). Además
// ignoraba por completo el offset.
func TestEqual(t *testing.T) {
	tests := []struct {
		name string
		a, b Magic
		want bool
	}{
		{"idénticos", MustParse("FF D8 FF"), MustParse("FF D8 FF"), true},
		{"distintos", MustParse("FF D8 FF"), MustParse("89 50 4E"), false},
		{"longitud distinta", MustParse("FF D8"), MustParse("FF D8 FF"), false},
		{"comodines iguales", MustParse("FF ?? FF"), MustParse("FF ?? FF"), true},
		{"comodín vs byte fijo", MustParse("FF ?? FF"), MustParse("FF D8 FF"), false},

		// El caso concreto que fallaba: 0x00 & 0xFF == 0 y 0x00 & 0x00 == 0.
		{"byte cero vs comodín", New([]byte{0x00}), MustParse("??"), false},

		// El offset forma parte de la identidad del patrón.
		{"offsets distintos", NewWithOffset([]byte("ftyp"), 4), New([]byte("ftyp")), false},
		{"mismo offset", NewWithOffset([]byte("ftyp"), 4), NewWithOffset([]byte("ftyp"), 4), true},
	}

	for _, tt := range tests {
		if got := tt.a.Equal(tt.b); got != tt.want {
			t.Errorf("%s: %s.Equal(%s) = %v, se esperaba %v", tt.name, tt.a, tt.b, got, tt.want)
		}
	}
}

// TestParseCompactWildcards: la ruta con comodines solo aceptaba tokens
// separados por espacios, mientras que la ruta sin comodines aceptaba ambas
// formas. "FF??FF" fallaba de forma sorprendente.
func TestParseCompactWildcards(t *testing.T) {
	compact, err := Parse("FF??FF")
	if err != nil {
		t.Fatalf("Parse(\"FF??FF\"): %v", err)
	}
	spaced := MustParse("FF ?? FF")

	if !compact.Equal(spaced) {
		t.Errorf("la forma compacta %s no equivale a la espaciada %s", compact, spaced)
	}
}

// TestFindWithWildcards ejercita el anclaje por el tramo fijo más largo, que
// evita recorrer posición a posición todo el disco.
func TestFindWithWildcards(t *testing.T) {
	mp4 := MustParse("?? ?? ?? ?? 66 74 79 70") // ancla en "ftyp"

	tests := []struct {
		data []byte
		want int
	}{
		{[]byte{0x00, 0x00, 0x00, 0x18, 'f', 't', 'y', 'p'}, 0},
		{[]byte{0xAA, 0xBB, 0x00, 0x00, 0x00, 0x18, 'f', 't', 'y', 'p'}, 2},
		{[]byte{0xAA, 0xBB, 0xCC}, -1},
		{make([]byte, 64), -1}, // todo ceros: no debe coincidir
	}

	for _, tt := range tests {
		if got := mp4.Find(tt.data); got != tt.want {
			t.Errorf("Find(%v) = %d, se esperaba %d", tt.data, got, tt.want)
		}
	}
}

func TestFindAll(t *testing.T) {
	m := MustParse("FF D8")
	data := []byte{0xFF, 0xD8, 0x00, 0xFF, 0xD8, 0x00, 0xFF, 0xD8}

	got := m.FindAll(data)
	want := []int{0, 3, 6}

	if len(got) != len(want) {
		t.Fatalf("FindAll() = %v, se esperaba %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("FindAll()[%d] = %d, se esperaba %d", i, got[i], want[i])
		}
	}
}

func TestParseOddLengthHex(t *testing.T) {
	for _, in := range []string{"FFD", "F", "FF D"} {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) no dio error con longitud hex impar", in)
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{"FF D8 FF", "FFD8FF", "FF ?? FF", "", "GG", "??", "**"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		m, err := Parse(s) // no debe hacer panic nunca
		if err == nil {
			_ = m.Hex()
			_ = m.Find([]byte{0x00, 0x01, 0x02})
			_ = m.Match([]byte{0x00, 0x01, 0x02})
		}
	})
}
