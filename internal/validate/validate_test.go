package validate

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"os"
	"path/filepath"
	"testing"
)

// =========================================================================
// Generadores de archivos reales
// =========================================================================

// jpegReal produce un JPEG genuino, codificado por la biblioteca estandar.
// Usar uno sintetico a mano no serviria: lo que se valida es el flujo Huffman.
func jpegReal(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.RGBA{uint8(x % 256), uint8(y % 256), uint8((x * y) % 256), 255})
		}
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 90}); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// pngReal produce un PNG genuino con CRCs correctos.
func pngReal(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.RGBA{uint8(x), uint8(y), 128, 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func escribir(t *testing.T, nombre string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), nombre)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// contaminar simula la fragmentacion: sustituye un tramo del archivo por datos
// de otro sitio, dejando intactos cabecera y cola.
func contaminar(data []byte, desde, hasta int, relleno byte) []byte {
	out := make([]byte, len(data))
	copy(out, data)
	if desde < 0 || hasta > len(out) || desde >= hasta {
		return out
	}
	for i := desde; i < hasta; i++ {
		out[i] = relleno
	}
	return out
}

// contaminarRuido hace lo mismo con datos de alta entropia, que es el caso que
// las heuristicas baratas NO detectan.
func contaminarRuido(data []byte, desde, hasta int) []byte {
	out := make([]byte, len(data))
	copy(out, data)
	if desde < 0 || hasta > len(out) || desde >= hasta {
		return out
	}
	var s uint32 = 0xC0FFEE
	for i := desde; i < hasta; i++ {
		s = s*1664525 + 1013904223
		out[i] = byte(s >> 24)
	}
	return out
}

// =========================================================================
// JPEG
// =========================================================================

func TestJPEGValido(t *testing.T) {
	path := escribir(t, "ok.jpg", jpegReal(t, 320, 240))

	res := File(path, "jpeg", DefaultOptions())
	if !res.OK() {
		t.Errorf("un JPEG valido se marco como %q: %s", res.Estado, res.Motivo)
	}
	if res.Metodo != "decodificacion" {
		t.Errorf("Metodo = %q, se esperaba decodificacion", res.Metodo)
	}
}

// TestJPEGFragmentadoBajaEntropia es la regresion del defecto capital [C1] en
// su variante mas comun: el hueco lo ocupan datos de baja entropia (ceros,
// estructuras del sistema de archivos, relleno).
func TestJPEGFragmentadoBajaEntropia(t *testing.T) {
	original := jpegReal(t, 320, 240)
	corrupto := contaminar(original, len(original)/3, len(original)*2/3, 0x5A)
	path := escribir(t, "frag.jpg", corrupto)

	// El archivo conserva los marcadores: por eso el carver lo daba por bueno.
	if !bytes.HasPrefix(corrupto, []byte{0xFF, 0xD8}) ||
		!bytes.HasSuffix(corrupto, []byte{0xFF, 0xD9}) {
		t.Fatal("el caso de prueba no reproduce el escenario: faltan los marcadores")
	}

	res := File(path, "jpeg", DefaultOptions())
	if res.OK() {
		t.Errorf("un JPEG con el 33%% de datos ajenos se dio por VALIDO: %+v", res)
	}
	t.Logf("detectado por %s: %s", res.Metodo, res.Motivo)
}

// TestJPEGFragmentadoAltaEntropia es el caso que ninguna heuristica barata
// detecta: el hueco lo ocupa otro archivo comprimido.
func TestJPEGFragmentadoAltaEntropia(t *testing.T) {
	original := jpegReal(t, 320, 240)
	corrupto := contaminarRuido(original, len(original)/3, len(original)*2/3)
	path := escribir(t, "frag2.jpg", corrupto)

	res := File(path, "jpeg", DefaultOptions())
	if res.OK() {
		t.Errorf("un JPEG contaminado con ruido se dio por VALIDO: %+v", res)
	}
	t.Logf("detectado por %s: %s", res.Metodo, res.Motivo)
}

func TestJPEGTruncado(t *testing.T) {
	original := jpegReal(t, 320, 240)
	path := escribir(t, "corto.jpg", original[:len(original)/2])

	if res := File(path, "jpeg", DefaultOptions()); res.OK() {
		t.Errorf("un JPEG truncado se dio por valido: %+v", res)
	}
}

// TestJPEGSinProfundo documenta que sin decodificacion NO se puede afirmar que
// un archivo esta intacto: el resultado es SinComprobar, nunca Valido.
func TestJPEGSinProfundo(t *testing.T) {
	original := jpegReal(t, 320, 240)
	corrupto := contaminarRuido(original, len(original)/3, len(original)*2/3)
	path := escribir(t, "frag3.jpg", corrupto)

	res := File(path, "jpeg", Options{Profundo: false})
	if res.Estado == Valido {
		t.Errorf("sin validacion profunda se afirmo que un corrupto es valido: %+v", res)
	}
	if res.Estado != SinComprobar {
		t.Errorf("Estado = %q, se esperaba %q", res.Estado, SinComprobar)
	}
}

// TestJPEGDimensionesAbsurdasNoAgotanMemoria: una cabecera corrupta puede
// declarar 60000x60000 pixeles. Decodificarla pediria gigabytes.
func TestJPEGDimensionesAbsurdas(t *testing.T) {
	original := jpegReal(t, 320, 240)
	path := escribir(t, "grande.jpg", original)

	// Tope de 1 pixel: fuerza la rama de "supera el tope".
	res := File(path, "jpeg", Options{Profundo: true, MaxPixeles: 1})
	if res.Estado != SinComprobar {
		t.Errorf("Estado = %q, se esperaba %q para una imagen sobre el tope",
			res.Estado, SinComprobar)
	}
}

// =========================================================================
// PNG
// =========================================================================

func TestPNGValido(t *testing.T) {
	path := escribir(t, "ok.png", pngReal(t, 200, 150))

	res := File(path, "png", DefaultOptions())
	if !res.OK() {
		t.Errorf("un PNG valido se marco como %q: %s", res.Estado, res.Motivo)
	}
	if res.Metodo != "crc" {
		t.Errorf("Metodo = %q, se esperaba crc", res.Metodo)
	}
}

// TestPNGFragmentado: el CRC por chunk detecta la contaminacion de forma
// determinista y sin descomprimir la imagen.
func TestPNGFragmentado(t *testing.T) {
	original := pngReal(t, 200, 150)
	corrupto := contaminarRuido(original, len(original)/2, len(original)/2+200)
	path := escribir(t, "frag.png", corrupto)

	res := File(path, "png", DefaultOptions())
	if res.OK() {
		t.Errorf("un PNG contaminado se dio por VALIDO: %+v", res)
	}
	t.Logf("detectado por %s: %s", res.Metodo, res.Motivo)
}

func TestPNGTruncado(t *testing.T) {
	original := pngReal(t, 200, 150)
	path := escribir(t, "corto.png", original[:len(original)-40])

	res := File(path, "png", DefaultOptions())
	if res.OK() {
		t.Errorf("un PNG sin IEND se dio por valido: %+v", res)
	}
}

func TestPNGFirmaIncorrecta(t *testing.T) {
	data := pngReal(t, 100, 100)
	data[1] = 'X'
	path := escribir(t, "malo.png", data)

	if res := File(path, "png", DefaultOptions()); res.OK() {
		t.Error("un PNG con firma incorrecta se dio por valido")
	}
}

// =========================================================================
// ZIP
// =========================================================================

func zipMinimo() []byte {
	// EOCD sin entradas: firma + 18 bytes de campos a cero.
	eocd := make([]byte, 22)
	copy(eocd, []byte{0x50, 0x4B, 0x05, 0x06})
	return eocd
}

func TestZIPValido(t *testing.T) {
	path := escribir(t, "ok.zip", zipMinimo())
	if res := File(path, "zip", DefaultOptions()); !res.OK() {
		t.Errorf("un ZIP minimo valido se marco como %q: %s", res.Estado, res.Motivo)
	}
}

func TestZIPSinEOCD(t *testing.T) {
	data := append([]byte{0x50, 0x4B, 0x03, 0x04}, bytes.Repeat([]byte{0}, 100)...)
	path := escribir(t, "sineocd.zip", data)

	if res := File(path, "zip", DefaultOptions()); res.OK() {
		t.Error("un ZIP sin EOCD se dio por valido")
	}
}

func TestZIPOffsetFueraDeRango(t *testing.T) {
	eocd := zipMinimo()
	binary.LittleEndian.PutUint16(eocd[10:12], 1)          // una entrada
	binary.LittleEndian.PutUint32(eocd[16:20], 0xFFFFFF00) // offset absurdo
	path := escribir(t, "malo.zip", eocd)

	if res := File(path, "zip", DefaultOptions()); res.OK() {
		t.Error("un ZIP con offset fuera de rango se dio por valido")
	}
}

// =========================================================================
// PDF
// =========================================================================

func TestPDFEnvolturaCorrecta(t *testing.T) {
	data := []byte("%PDF-1.7\n" + string(bytes.Repeat([]byte("x"), 200)) +
		"\nstartxref\n123\n%%EOF")
	path := escribir(t, "ok.pdf", data)

	res := File(path, "pdf", DefaultOptions())
	// Un PDF con envoltura correcta NO se afirma valido: no se interpreta el
	// contenido, y decir "valido" seria mentir sobre lo comprobado.
	if res.Estado != SinComprobar {
		t.Errorf("Estado = %q, se esperaba %q", res.Estado, SinComprobar)
	}
}

func TestPDFSinEOF(t *testing.T) {
	data := []byte("%PDF-1.7\n" + string(bytes.Repeat([]byte("x"), 200)))
	path := escribir(t, "malo.pdf", data)

	if res := File(path, "pdf", DefaultOptions()); res.Estado != Corrupto {
		t.Errorf("un PDF sin %%%%EOF dio %q", res.Estado)
	}
}

// =========================================================================
// Contrato general
// =========================================================================

// TestTipoSinValidadorNoAfirmaValidez es una regla central del diseno: no se
// puede decir que un archivo esta intacto solo porque no se sabe mirarlo.
func TestTipoSinValidadorNoAfirmaValidez(t *testing.T) {
	path := escribir(t, "algo.mp4", bytes.Repeat([]byte{0x42}, 1000))

	res := File(path, "mp4", DefaultOptions())
	if res.Estado == Valido {
		t.Error("un tipo sin validador se afirmo VALIDO")
	}
	if res.Estado != SinComprobar {
		t.Errorf("Estado = %q, se esperaba %q", res.Estado, SinComprobar)
	}
}

func TestArchivoInexistente(t *testing.T) {
	path := filepath.Join(t.TempDir(), "no-existe.jpg")
	if res := File(path, "jpeg", DefaultOptions()); res.OK() {
		t.Error("un archivo inexistente se dio por valido")
	}
}

func TestArchivoVacio(t *testing.T) {
	for _, tipo := range Tipos() {
		path := escribir(t, "vacio", nil)
		if res := File(path, tipo, DefaultOptions()); res.OK() {
			t.Errorf("%s: un archivo vacio se dio por valido", tipo)
		}
	}
}

// TestNoHacePanicConBasura: los validadores reciben datos de un disco danado.
func TestNoHacePanicConBasura(t *testing.T) {
	entradas := [][]byte{
		{},
		{0xFF},
		{0xFF, 0xD8, 0xFF},
		bytes.Repeat([]byte{0xFF}, 5000),
		bytes.Repeat([]byte{0x00}, 5000),
		[]byte("\x89PNG\r\n\x1a\n"),
	}

	for i, data := range entradas {
		for _, tipo := range Tipos() {
			path := escribir(t, "basura", data)
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("panic con entrada %d, tipo %s: %v", i, tipo, r)
					}
				}()
				File(path, tipo, DefaultOptions())
			}()
		}
	}
}

func FuzzValidateJPEG(f *testing.F) {
	f.Add([]byte{0xFF, 0xD8, 0xFF, 0xD9})
	f.Add([]byte{})

	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, data []byte) {
		path := filepath.Join(dir, "fuzz.jpg")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Skip()
		}
		// Tope bajo para que el fuzzer no intente decodificar imagenes enormes.
		File(path, "jpeg", Options{Profundo: true, MaxPixeles: 1 << 16})
	})
}

func FuzzValidatePNG(f *testing.F) {
	f.Add([]byte("\x89PNG\r\n\x1a\n"))
	f.Add([]byte{})

	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, data []byte) {
		path := filepath.Join(dir, "fuzz.png")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Skip()
		}
		File(path, "png", DefaultOptions())
	})
}

// crc32Helper deja constancia de que el CRC de PNG es el IEEE estandar; si
// alguna vez falla, el problema esta en la eleccion de polinomio.
func TestCRC32EsIEEE(t *testing.T) {
	h := crc32.NewIEEE()
	h.Write([]byte("IEND"))
	if got := h.Sum32(); got != 0xAE426082 {
		t.Errorf("CRC de IEND = %08X, se esperaba AE426082", got)
	}
}

// TestJPEGRealesNoDanFalsoPositivo protege el umbral de maxRunJPEG.
//
// El riesgo de una heuristica de rachas es rechazar fotos legitimas: una imagen
// con grandes zonas uniformes (cielo, pared, fondo negro) podria producir
// rachas largas. Se midio que no ocurre —el techo es 129 sin importar tamano ni
// contenido— y este test lo mantiene cierto ante cambios futuros.
func TestJPEGRealesNoDanFalsoPositivo(t *testing.T) {
	casos := []struct {
		nombre string
		pixel  func(x, y int) color.RGBA
	}{
		{"cielo liso", func(x, y int) color.RGBA { return color.RGBA{200, 220, 255, 255} }},
		{"negro puro", func(x, y int) color.RGBA { return color.RGBA{0, 0, 0, 255} }},
		{"blanco puro", func(x, y int) color.RGBA { return color.RGBA{255, 255, 255, 255} }},
		{"degradado", func(x, y int) color.RGBA { return color.RGBA{uint8(x / 3), uint8(y / 3), 128, 255} }},
		{"detalle alto", func(x, y int) color.RGBA { return color.RGBA{uint8(x * y), uint8(x ^ y), uint8(x + y), 255} }},
	}

	for _, c := range casos {
		for _, q := range []int{50, 75, 90, 100} {
			img := image.NewRGBA(image.Rect(0, 0, 640, 480))
			for y := 0; y < 480; y++ {
				for x := 0; x < 640; x++ {
					img.Set(x, y, c.pixel(x, y))
				}
			}
			var buf bytes.Buffer
			if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: q}); err != nil {
				t.Fatal(err)
			}

			path := escribir(t, "real.jpg", buf.Bytes())
			res := File(path, "jpeg", DefaultOptions())
			if !res.OK() {
				t.Errorf("FALSO POSITIVO en %q q=%d: %s (%s)",
					c.nombre, q, res.Estado, res.Motivo)
			}
		}
	}
}
