package namerecovery

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
)

// TestSanitizeBlocksTraversal comprueba que la delegación en
// output.SanitizeFilename mantiene la frontera de seguridad. El nombre viene de
// bytes de un disco ajeno y la herramienta suele correr como root.
func TestSanitizeBlocksTraversal(t *testing.T) {
	for _, hostile := range []string{
		"../../../etc/cron.d/x",
		`..\..\Windows\System32\evil.dll`,
		"/etc/passwd",
		"..",
	} {
		got := Sanitize(hostile)
		if strings.ContainsAny(got, `/\`) {
			t.Errorf("Sanitize(%q) = %q: conserva separadores", hostile, got)
		}
		if got != "" {
			joined := filepath.ToSlash(filepath.Join("/base", got))
			if !strings.HasPrefix(joined, "/base/") {
				t.Errorf("Sanitize(%q) = %q escapa: %q", hostile, got, joined)
			}
		}
	}
}

func TestLooksLikeFilename(t *testing.T) {
	valid := []string{
		"foto.jpg", "IMG_1234.JPG", "Vacaciones 2024.png",
		"informe-final.pdf", "video.mp4", "a.jpeg",
	}
	invalid := []string{
		"",                                // vacío
		"foto",                            // sin extensión
		".jpg",                            // sin nombre
		"...jpg",                          // nombre solo de puntos
		"archivo.xyz",                     // extensión desconocida
		"con/barra.jpg",                   // separador de ruta
		`con\barra.jpg`,                   // separador de ruta
		strings.Repeat("a", 300) + ".jpg", // absurdamente largo
	}

	for _, s := range valid {
		if !looksLikeFilename(s) {
			t.Errorf("looksLikeFilename(%q) = false, se esperaba true", s)
		}
	}
	for _, s := range invalid {
		if looksLikeFilename(s) {
			t.Errorf("looksLikeFilename(%q) = true, se esperaba false", s)
		}
	}
}

// TestScanNearbyFindsUTF16Name: FAT32 (LFN) y NTFS ($FILE_NAME) guardan los
// nombres en UTF-16LE, así que el barrido tiene que cubrir esa codificación.
func TestScanNearbyFindsUTF16Name(t *testing.T) {
	disk := make([]byte, 128<<10)

	name := "Vacaciones2024.jpg"
	units := utf16.Encode([]rune(name))
	at := 60 << 10
	for i, u := range units {
		disk[at+i*2] = byte(u)
		disk[at+i*2+1] = byte(u >> 8)
	}

	// El archivo empieza después del nombre, como en un directorio real.
	fileOffset := int64(70 << 10)

	r := NewResolver(bytes.NewReader(disk))
	got := r.scanNearby(fileOffset)

	if got != name {
		t.Errorf("scanNearby() = %q, se esperaba %q", got, name)
	}
}

func TestScanNearbyFindsASCIIName(t *testing.T) {
	disk := make([]byte, 128<<10)
	name := "IMG_4567.JPG"
	copy(disk[60<<10:], name)

	r := NewResolver(bytes.NewReader(disk))
	if got := r.scanNearby(70 << 10); got != name {
		t.Errorf("scanNearby() = %q, se esperaba %q", got, name)
	}
}

func TestScanNearbyRejectsGarbage(t *testing.T) {
	// Bytes aleatorios sin ninguna extensión conocida: no debe inventarse nada.
	disk := make([]byte, 128<<10)
	for i := range disk {
		disk[i] = byte(i % 251)
	}

	r := NewResolver(bytes.NewReader(disk))
	if got := r.scanNearby(70 << 10); got != "" {
		t.Errorf("scanNearby() = %q sobre datos aleatorios, se esperaba vacío", got)
	}
}

// TestScanNearbyIsSanitized: cualquier nombre que salga del barrido ya tiene
// que venir saneado, porque procede directamente del disco auditado.
func TestScanNearbyIsSanitized(t *testing.T) {
	disk := make([]byte, 128<<10)
	copy(disk[60<<10:], "....jpg")

	r := NewResolver(bytes.NewReader(disk))
	got := r.scanNearby(70 << 10)

	if strings.ContainsAny(got, `/\`) || got == ".." {
		t.Errorf("scanNearby() devolvió un nombre sin sanear: %q", got)
	}
}

// TestNameFromXMP: Lightroom y Photoshop dejan el nombre original en el paquete
// XMP, que es la fuente más fiable porque viaja dentro del propio archivo.
func TestNameFromXMP(t *testing.T) {
	xmp := `<?xpacket begin=""?><x:xmpmeta xmlns:x="adobe:ns:meta/">` +
		`<rdf:RDF><rdf:Description xmpMM:PreservedFileName="MiFoto.jpg">` +
		`</rdf:Description></rdf:RDF></x:xmpmeta>`

	if got := nameFromXMP([]byte(xmp)); got != "MiFoto.jpg" {
		t.Errorf("nameFromXMP() = %q, se esperaba %q", got, "MiFoto.jpg")
	}
}

func TestNameFromXMPTruncated(t *testing.T) {
	// Un paquete XMP cortado a la mitad es lo normal en un archivo recuperado.
	full := `<x:xmpmeta><rdf:Description xmpMM:PreservedFileName="Foto.jpg"></x:xmpmeta>`
	for cut := 0; cut < len(full); cut++ {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic con %d bytes: %v", cut, r)
				}
			}()
			nameFromXMP([]byte(full[:cut]))
		}()
	}
}

func TestEnsureExt(t *testing.T) {
	tests := []struct{ name, ext, want string }{
		{"foto", ".jpg", "foto.jpg"},
		{"foto.jpg", ".jpg", "foto.jpg"},
		{"foto.JPG", ".jpg", "foto.JPG"}, // la extensión ya está, sin duplicar
		{"foto.png", ".jpg", "foto.png.jpg"},
		{"foto", "", "foto"},
	}
	for _, tt := range tests {
		if got := ensureExt(tt.name, tt.ext); got != tt.want {
			t.Errorf("ensureExt(%q, %q) = %q, se esperaba %q", tt.name, tt.ext, got, tt.want)
		}
	}
}

func TestResolveReturnsEmptyWhenNothingFound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jpeg_000001.jpg")
	if err := os.WriteFile(path, []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10}, 0o644); err != nil {
		t.Fatal(err)
	}

	r := NewResolver(bytes.NewReader(make([]byte, 1<<20)))
	got, err := r.Resolve(path, 500<<10, 6)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// Devolver vacío es un resultado válido y frecuente, no un error.
	if got != "" {
		t.Errorf("Resolve() = %q, se esperaba vacío sin pistas de nombre", got)
	}
}

func FuzzLooksLikeFilename(f *testing.F) {
	f.Add("foto.jpg")
	f.Add("../etc/passwd.jpg")
	f.Add("")

	f.Fuzz(func(t *testing.T, s string) {
		if looksLikeFilename(s) {
			// Todo lo que se acepte tiene que sobrevivir al saneado sin escapar.
			got := Sanitize(s)
			if strings.ContainsAny(got, `/\`) {
				t.Fatalf("se aceptó %q y Sanitize dejó separadores: %q", s, got)
			}
		}
	})
}
