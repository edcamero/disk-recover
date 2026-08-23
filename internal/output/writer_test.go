package output

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSanitizeFilenameBlocksTraversal es la regresión de [C6]. El nombre viene
// de los bytes de un disco ajeno y la herramienta suele correr como root: nada
// que salga de aquí puede conservar la capacidad de salir del directorio.
func TestSanitizeFilenameBlocksTraversal(t *testing.T) {
	hostile := []string{
		"../../../etc/cron.d/x",
		"..\\..\\..\\Windows\\System32\\evil.dll",
		"/etc/passwd",
		`C:\Windows\evil.exe`,
		"..",
		".",
		"....",
		"foo/../../bar.jpg",
	}

	for _, name := range hostile {
		got := SanitizeFilename(name)

		if strings.ContainsAny(got, `/\`) {
			t.Errorf("SanitizeFilename(%q) = %q: conserva separadores de ruta", name, got)
		}
		if got == ".." || got == "." {
			t.Errorf("SanitizeFilename(%q) = %q: sigue siendo un componente de recorrido", name, got)
		}

		// La prueba de fuego: unir el resultado no puede escapar del base.
		if got != "" {
			joined := filepath.Join("/base", got)
			if !strings.HasPrefix(filepath.ToSlash(joined), "/base/") {
				t.Errorf("SanitizeFilename(%q) = %q escapa: %q", name, got, joined)
			}
		}
	}
}

// TestSanitizeFilenameLongExtension es la regresión del panic de [I17]:
// name[:200-len(ext)] con una extensión de más de 200 bytes da índice negativo.
func TestSanitizeFilenameLongExtension(t *testing.T) {
	name := "foto." + strings.Repeat("x", 300)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("SanitizeFilename hizo panic con extensión larga: %v", r)
		}
	}()

	got := SanitizeFilename(name)
	if len(got) > maxNameBytes {
		t.Errorf("resultado de %d bytes, máximo %d", len(got), maxNameBytes)
	}
}

func TestSanitizeFilenameWindowsReserved(t *testing.T) {
	for _, name := range []string{"NUL", "nul.jpg", "CON", "com1.txt", "LPT9.png"} {
		got := SanitizeFilename(name)
		base := got
		if i := strings.Index(base, "."); i > 0 {
			base = base[:i]
		}
		if windowsReserved[strings.ToUpper(base)] {
			t.Errorf("SanitizeFilename(%q) = %q: sigue siendo un nombre reservado", name, got)
		}
	}
}

func TestSanitizeFilenameControlChars(t *testing.T) {
	got := SanitizeFilename("fo\x00to\x01\x1f.jpg")
	for _, r := range got {
		if r < 0x20 || r == 0x7F {
			t.Errorf("SanitizeFilename dejó un carácter de control %q en %q", r, got)
		}
	}
}

func TestSanitizeFilenameValidNamesSurvive(t *testing.T) {
	for _, name := range []string{"foto.jpg", "Vacaciones 2024.png", "informe_final-v2.pdf", "café.jpg"} {
		if got := SanitizeFilename(name); got != name {
			t.Errorf("SanitizeFilename(%q) = %q, se esperaba que no cambiara", name, got)
		}
	}
}

// TestSanitizeRelPathConfines: los componentes ".." se DESCARTAN, no se
// interpretan. Así "../../etc" queda en "etc", que es seguro (cae dentro del
// base) aunque no sea vacío. Lo que se garantiza es el confinamiento, no que la
// ruta desaparezca.
func TestSanitizeRelPathConfines(t *testing.T) {
	tests := []struct{ in, want string }{
		{"DCIM/100CANON", filepath.Join("DCIM", "100CANON")},
		{"../../etc", "etc"},
		{"a/../../../b", filepath.Join("a", "b")},
		{"", ""},
		{"./fotos", "fotos"},
		{"..", ""},
		{"../..", ""},
	}

	for _, tt := range tests {
		got := SanitizeRelPath(tt.in)

		if got != tt.want {
			t.Errorf("SanitizeRelPath(%q) = %q, se esperaba %q", tt.in, got, tt.want)
		}

		// La propiedad de seguridad, que es lo que de verdad importa.
		joined := filepath.ToSlash(filepath.Join("/base", got))
		if joined != "/base" && !strings.HasPrefix(joined, "/base/") {
			t.Errorf("SanitizeRelPath(%q) = %q escapa del base: %q", tt.in, got, joined)
		}
		if strings.Contains(filepath.ToSlash(got), "..") {
			t.Errorf("SanitizeRelPath(%q) = %q conserva un componente de recorrido", tt.in, got)
		}
	}
}

// TestReserveNameNoCollision es la regresión de [C4]: la versión anterior usaba
// offset%0xFFFF como sufijo "único" y os.Rename sobrescribía en silencio, así
// que dos fotos distintas con el mismo nombre se destruían entre sí.
func TestReserveNameNoCollision(t *testing.T) {
	dir := t.TempDir()

	seen := make(map[string]bool)
	for i := 0; i < 50; i++ {
		path, renamed, err := reserveName(dir, "foto.jpg")
		if err != nil {
			t.Fatalf("reserveName #%d: %v", i, err)
		}
		if seen[path] {
			t.Fatalf("reserveName devolvió %q dos veces: se sobrescribiría un archivo", path)
		}
		seen[path] = true

		if i > 0 && !renamed {
			t.Errorf("reserveName #%d no marcó el renombrado por colisión", i)
		}
		if err := os.WriteFile(path, []byte{byte(i)}, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	entries, _ := os.ReadDir(dir)
	if len(entries) != 50 {
		t.Errorf("quedaron %d archivos, se esperaban 50: hubo sobrescritura", len(entries))
	}
}

func TestSaveComputesSHA256(t *testing.T) {
	srcFile := filepath.Join(t.TempDir(), "origen.img")
	if err := os.WriteFile(srcFile, []byte("datos de prueba"), 0o644); err != nil {
		t.Fatal(err)
	}

	w, err := NewSafeWriter(t.TempDir(), srcFile)
	if err != nil {
		t.Fatalf("NewSafeWriter: %v", err)
	}

	res, err := w.Save(strings.NewReader("hola"), "saludo.txt")
	if err != nil {
		t.Fatalf("Save: %v", err)
	}

	// sha256("hola")
	const want = "b221d9dbb083a7f33428d7c2a3c3198ae925614d70210e28716ccaa7cd4ddb79"
	if res.SHA256 != want {
		t.Errorf("SHA256 = %q, se esperaba %q", res.SHA256, want)
	}
	if res.Size != 4 {
		t.Errorf("Size = %d, se esperaba 4", res.Size)
	}

	data, err := os.ReadFile(res.FinalPath)
	if err != nil {
		t.Fatalf("no se pudo leer el archivo guardado: %v", err)
	}
	if string(data) != "hola" {
		t.Errorf("contenido = %q, se esperaba %q", data, "hola")
	}
}

// TestSaveLeavesNoTempFiles: un .tmp huérfano indica una ruta de error sucia.
func TestSaveLeavesNoTempFiles(t *testing.T) {
	srcFile := filepath.Join(t.TempDir(), "origen.img")
	if err := os.WriteFile(srcFile, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	destDir := t.TempDir()

	w, err := NewSafeWriter(destDir, srcFile)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err := w.Save(strings.NewReader("contenido"), "archivo.bin"); err != nil {
			t.Fatal(err)
		}
	}

	entries, _ := os.ReadDir(destDir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("quedó un archivo temporal: %s", e.Name())
		}
	}
}

func TestPlaceMovesWithoutOverwriting(t *testing.T) {
	srcDir := t.TempDir()
	destDir := filepath.Join(t.TempDir(), "destino")

	for i := 0; i < 3; i++ {
		stage := filepath.Join(srcDir, "stage", "f")
		if err := os.MkdirAll(filepath.Dir(stage), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(stage, []byte{byte(i)}, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Place(stage, destDir, "foto.jpg"); err != nil {
			t.Fatalf("Place #%d: %v", i, err)
		}
	}

	entries, _ := os.ReadDir(destDir)
	if len(entries) != 3 {
		t.Errorf("quedaron %d archivos en el destino, se esperaban 3", len(entries))
	}
}
