package classifier

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// =========================================================================
// Constructores de imágenes sintéticas
// =========================================================================

// buildJPEG arma un JPEG con un SOF0 que declara las dimensiones dadas, y
// opcionalmente un bloque EXIF con marca y modelo de cámara.
func buildJPEG(width, height int, camera string, padTo int) []byte {
	var b []byte
	b = append(b, 0xFF, 0xD8) // SOI

	if camera != "" {
		b = append(b, buildEXIFSegment(camera)...)
	}

	// SOF0: longitud(2) precisión(1) alto(2) ancho(2) componentes(1)
	sof := []byte{0xFF, 0xC0, 0x00, 0x0B, 0x08}
	sof = binary.BigEndian.AppendUint16(sof, uint16(height))
	sof = binary.BigEndian.AppendUint16(sof, uint16(width))
	sof = append(sof, 0x03)
	b = append(b, sof...)

	b = append(b, 0xFF, 0xDA) // SOS
	for len(b) < padTo {
		b = append(b, 0x42)
	}
	b = append(b, 0xFF, 0xD9) // EOI
	return b
}

// buildEXIFSegment crea un APP1 con un IFD0 que lleva Make y Model.
func buildEXIFSegment(camera string) []byte {
	// TIFF little-endian con dos entradas ASCII cuyos valores van al final.
	tiff := []byte{'I', 'I', 42, 0, 8, 0, 0, 0}

	entries := 2
	tiff = binary.LittleEndian.AppendUint16(tiff, uint16(entries))

	value := append([]byte(camera), 0)
	// Los valores se colocan tras el IFD: 8 (cabecera) + 2 (contador)
	// + entries*12 + 4 (siguiente IFD).
	valueOffset := 8 + 2 + entries*12 + 4

	for _, tag := range []uint16{tagMake, tagModel} {
		tiff = binary.LittleEndian.AppendUint16(tiff, tag)
		tiff = binary.LittleEndian.AppendUint16(tiff, 2) // ASCII
		tiff = binary.LittleEndian.AppendUint32(tiff, uint32(len(value)))
		tiff = binary.LittleEndian.AppendUint32(tiff, uint32(valueOffset))
	}
	tiff = binary.LittleEndian.AppendUint32(tiff, 0) // sin siguiente IFD
	tiff = append(tiff, value...)

	payload := append([]byte("Exif\x00\x00"), tiff...)

	seg := []byte{0xFF, 0xE1}
	seg = binary.BigEndian.AppendUint16(seg, uint16(len(payload)+2))
	return append(seg, payload...)
}

func buildPNG(width, height int, padTo int) []byte {
	b := []byte("\x89PNG\r\n\x1a\n")
	b = binary.BigEndian.AppendUint32(b, 13)
	b = append(b, []byte("IHDR")...)
	b = binary.BigEndian.AppendUint32(b, uint32(width))
	b = binary.BigEndian.AppendUint32(b, uint32(height))
	b = append(b, 8, 6, 0, 0, 0)
	for len(b) < padTo {
		b = append(b, 0x00)
	}
	return b
}

func writeTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// =========================================================================
// Dimensiones sin decodificar
// =========================================================================

func TestReadDimensions(t *testing.T) {
	tests := []struct {
		name          string
		data          []byte
		width, height int
	}{
		{"jpeg", buildJPEG(1920, 1080, "", 0), 1920, 1080},
		{"jpeg pequeño", buildJPEG(32, 32, "", 0), 32, 32},
		{"png", buildPNG(800, 600, 0), 800, 600},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, h, ok := readDimensions(tt.data)
			if !ok {
				t.Fatal("readDimensions no reconoció el formato")
			}
			if w != tt.width || h != tt.height {
				t.Errorf("dimensiones = %dx%d, se esperaba %dx%d", w, h, tt.width, tt.height)
			}
		})
	}
}

func TestReadDimensionsTruncated(t *testing.T) {
	// Un archivo cortado a la mitad no debe hacer panic, solo devolver false.
	full := buildJPEG(1920, 1080, "", 0)
	for cut := 0; cut < len(full); cut++ {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic con %d bytes: %v", cut, r)
				}
			}()
			readDimensions(full[:cut])
		}()
	}
}

func FuzzReadDimensions(f *testing.F) {
	f.Add(buildJPEG(100, 100, "", 0))
	f.Add(buildPNG(100, 100, 0))
	f.Add([]byte{0xFF, 0xD8, 0xFF})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		w, h, ok := readDimensions(data) // no debe hacer panic
		if ok && (w <= 0 || h <= 0) {
			t.Fatalf("ok con dimensiones inválidas: %dx%d", w, h)
		}
	})
}

// =========================================================================
// EXIF
// =========================================================================

func TestParseEXIFCamera(t *testing.T) {
	data := buildJPEG(4000, 3000, "Canon EOS R5", 0)

	var ex exifData
	parseEXIF(data, &ex)

	if !ex.HasEXIF {
		t.Fatal("no se detectó el bloque EXIF")
	}
	if ex.Make != "Canon EOS R5" {
		t.Errorf("Make = %q, se esperaba %q", ex.Make, "Canon EOS R5")
	}
	if !ex.hasCameraInfo() {
		t.Error("hasCameraInfo() = false pese a haber marca")
	}
}

func FuzzParseEXIF(f *testing.F) {
	f.Add(buildJPEG(100, 100, "Nikon", 0))
	f.Add([]byte{0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x08, 'E', 'x', 'i', 'f', 0, 0})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		var ex exifData
		parseEXIF(data, &ex) // no debe hacer panic con ninguna entrada
	})
}

// =========================================================================
// Clasificación
// =========================================================================

// TestClassifyPhotoWithEXIF: una foto de cámara es el caso claro de contenido
// de usuario. Ningún icono lleva marca y modelo de cámara.
func TestClassifyPhotoWithEXIF(t *testing.T) {
	data := buildJPEG(4000, 3000, "Canon EOS R5", 2<<20)
	path := writeTemp(t, "foto.jpg", data)

	res, err := New().Classify(path, 12345)
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}

	if !res.IsUserContent {
		t.Errorf("IsUserContent = false para una foto con EXIF de cámara (razones: %v)", res.Reasons)
	}
	if res.Category != CategoryPhoto {
		t.Errorf("Category = %q, se esperaba %q", res.Category, CategoryPhoto)
	}
	if res.Camera == "" {
		t.Error("no se propagó la cámara al resultado")
	}
	if res.Offset != 12345 {
		t.Errorf("Offset = %d, se esperaba 12345", res.Offset)
	}
}

// TestClassifyIcon: un PNG cuadrado de 32x32 y pocos KB es inequívocamente un
// recurso de interfaz.
func TestClassifyIcon(t *testing.T) {
	path := writeTemp(t, "icono.png", buildPNG(32, 32, 2000))

	res, err := New().Classify(path, 0)
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}

	if res.IsUserContent {
		t.Errorf("un icono de 32x32 se clasificó como contenido de usuario (razones: %v)", res.Reasons)
	}
	if res.Category != CategoryIcon {
		t.Errorf("Category = %q, se esperaba %q", res.Category, CategoryIcon)
	}
}

// TestConfidenceIsAboutTheVerdict es la regresión conceptual de [I10]. Antes la
// confianza se usaba invertida: se mandaba a system_files lo de confianza BAJA
// y se dejaba en unknown lo identificado con confianza ALTA. Ahora Confidence
// mide la seguridad EN EL VEREDICTO, sea cual sea, y por tanto nunca es
// negativa ni pasa de 1.
func TestConfidenceIsAboutTheVerdict(t *testing.T) {
	cases := []struct {
		name string
		path string
	}{
		{"foto de cámara", writeTemp(t, "foto.jpg", buildJPEG(4000, 3000, "Sony A7", 3<<20))},
		{"icono", writeTemp(t, "icono.png", buildPNG(16, 16, 500))},
		{"ambiguo", writeTemp(t, "medio.png", buildPNG(500, 400, 150<<10))},
	}

	for _, c := range cases {
		res, err := New().Classify(c.path, 0)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if res.Confidence < 0 || res.Confidence > 1 {
			t.Errorf("%s: Confidence = %f, fuera de [0,1]", c.name, res.Confidence)
		}
		t.Logf("%s: user=%v cat=%s conf=%.2f", c.name, res.IsUserContent, res.Category, res.Confidence)
	}
}

func TestClassifyMissingFile(t *testing.T) {
	if _, err := New().Classify(filepath.Join(t.TempDir(), "no-existe.jpg"), 0); err == nil {
		t.Error("se esperaba error con un archivo inexistente")
	}
}

func TestClassifyEmptyFile(t *testing.T) {
	path := writeTemp(t, "vacio.jpg", nil)

	res, err := New().Classify(path, 0)
	if err != nil {
		t.Fatalf("Classify con archivo vacío: %v", err)
	}
	if res.IsUserContent {
		t.Error("un archivo vacío se clasificó como contenido de usuario")
	}
}

// TestClassifyTruncatedFile: los archivos truncados son mayoría en una
// recuperación; clasificarlos no puede hacer panic.
func TestClassifyTruncatedFile(t *testing.T) {
	full := buildJPEG(1920, 1080, "Canon", 4096)
	for _, cut := range []int{0, 1, 2, 5, 20, 100, 500} {
		if cut > len(full) {
			continue
		}
		path := writeTemp(t, "cortado.jpg", full[:cut])
		if _, err := New().Classify(path, 0); err != nil {
			t.Errorf("Classify falló con %d bytes: %v", cut, err)
		}
	}
}

func TestIsIconSize(t *testing.T) {
	icons := [][2]int{{16, 16}, {32, 32}, {48, 48}, {256, 256}}
	notIcons := [][2]int{{1080, 1080}, {32, 64}, {33, 33}, {1920, 1080}}

	for _, d := range icons {
		if !isIconSize(d[0], d[1]) {
			t.Errorf("isIconSize(%d,%d) = false, se esperaba true", d[0], d[1])
		}
	}
	for _, d := range notIcons {
		if isIconSize(d[0], d[1]) {
			t.Errorf("isIconSize(%d,%d) = true, se esperaba false", d[0], d[1])
		}
	}
}

func TestIsPhotoAspect(t *testing.T) {
	if !isPhotoAspect(4000, 3000) { // 4:3
		t.Error("4000x3000 debería ser proporción de foto")
	}
	if !isPhotoAspect(1920, 1080) { // 16:9
		t.Error("1920x1080 debería ser proporción de foto")
	}
	if isPhotoAspect(1000, 1000) { // cuadrado
		t.Error("1000x1000 no debería ser proporción de foto")
	}
}

// TestCameraName: muchas cámaras repiten el fabricante en marca y modelo
// (Nikon graba Make="NIKON CORPORATION", Model="NIKON Z 6"), y concatenarlos a
// secas deja la repetición a la vista del usuario en el .meta.json.
func TestCameraName(t *testing.T) {
	tests := []struct{ make_, model, want string }{
		{"Canon", "EOS R5", "Canon EOS R5"},
		{"NIKON CORPORATION", "NIKON Z 6", "NIKON Z 6"},
		{"Canon EOS R5", "Canon EOS R5", "Canon EOS R5"},
		{"Apple", "iPhone 15 Pro", "Apple iPhone 15 Pro"},
		{"", "Pixel 8", "Pixel 8"},
		{"Sony", "", "Sony"},
		{"", "", ""},
	}
	for _, tt := range tests {
		if got := cameraName(tt.make_, tt.model); got != tt.want {
			t.Errorf("cameraName(%q, %q) = %q, se esperaba %q", tt.make_, tt.model, got, tt.want)
		}
	}
}

// TestDateTakenOmittedWhenAbsent: omitempty no funciona sobre un time.Time por
// valor, así que una fecha ausente se serializaba como "0001-01-01T00:00:00Z".
func TestDateTakenOmittedWhenAbsent(t *testing.T) {
	path := writeTemp(t, "sinfecha.png", buildPNG(64, 64, 5000))

	res, err := New().Classify(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("0001-01-01")) {
		t.Errorf("el JSON incluye la fecha cero: %s", data)
	}
}
