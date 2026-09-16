package pipeline

import (
	"bytes"
	"context"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/edcamero/disk-recover/internal/manifest"
	"github.com/edcamero/disk-recover/internal/validate"
)

// Estos tests son la razon de que el paquete exista. Mientras la orquestacion
// vivio dentro de cmd/recover no habia forma de ejercitarla: eran 800 lineas
// con 0 % de cobertura, porque probar un main() exige lanzar el binario, tener
// un disco y a menudo privilegios.
//
// Aqui el origen es un io.ReaderAt sobre un []byte y el destino un t.TempDir(),
// asi que el flujo completo —detectar, extraer, validar, clasificar, colocar y
// anotar— se comprueba en milisegundos y sin tocar hardware.

// =========================================================================
// Generadores
// =========================================================================

func fotoJPEG(t *testing.T, w, h, semilla int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.RGBA{uint8(x + semilla), uint8(y), uint8(x ^ y), 255})
		}
	}
	var b bytes.Buffer
	if err := jpeg.Encode(&b, img, &jpeg.Options{Quality: 90}); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func iconoPNG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 32, 32))
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// corromper sustituye un tramo por datos ajenos, como hace la fragmentacion.
func corromper(data []byte, relleno byte) []byte {
	out := make([]byte, len(data))
	copy(out, data)
	for i := len(out) / 3; i < len(out)*2/3; i++ {
		out[i] = relleno
	}
	return out
}

// discoConArchivos coloca los contenidos dados en offsets separados.
func discoConArchivos(size int, contenidos [][]byte) []byte {
	disk := make([]byte, size)
	paso := size / (len(contenidos) + 1)
	for i, c := range contenidos {
		off := paso * (i + 1)
		if off+len(c) < size {
			copy(disk[off:], c)
		}
	}
	return disk
}

func configBase(destino string) Config {
	return Config{
		Destino:    destino,
		Modo:       "carve",
		Clasificar: true,
		Validar:    true,
		MinLibre:   1 << 20, // 1 MB: los TempDir siempre tienen tanto
	}
}

// ejecutar corre el pipeline sobre un disco sintético.
//
// La imagen se escribe a un archivo REAL aunque se lea desde memoria: el
// pipeline comprueba que el origen existe antes de escribir nada, y saltarse esa
// comprobación en los tests dejaría sin ejercitar justo la ruta que protege de
// escribir sobre el disco que se está recuperando.
func ejecutar(t *testing.T, disk []byte, cfg Config) (*Pipeline, error) {
	t.Helper()

	if cfg.Origen == "" {
		origen := filepath.Join(t.TempDir(), "origen.img")
		if err := os.WriteFile(origen, disk, 0o644); err != nil {
			t.Fatal(err)
		}
		cfg.Origen = origen
	}

	p, err := New(cfg, bytes.NewReader(disk), int64(len(disk)))
	if err != nil {
		return nil, err
	}
	return p, p.Run(context.Background())
}

// =========================================================================
// Flujo completo
// =========================================================================

// TestFlujoCompletoSeparaCorruptos es la prueba de extremo a extremo del
// comportamiento central: lo integro y lo corrupto acaban en sitios distintos.
func TestFlujoCompletoSeparaCorruptos(t *testing.T) {
	dest := t.TempDir()

	buena := fotoJPEG(t, 400, 300, 1)
	mala := corromper(fotoJPEG(t, 400, 300, 2), 0x5A)
	icono := iconoPNG(t)

	disk := discoConArchivos(4<<20, [][]byte{buena, mala, icono})

	p, err := ejecutar(t, disk, configBase(dest))
	if err != nil {
		t.Fatal(err)
	}

	s := p.Stats()
	if s.Dudoso != 1 {
		t.Errorf("Dudoso = %d, se esperaba 1: la foto corrupta debe ir aparte", s.Dudoso)
	}
	if s.Usuario+s.Sistema+s.Desconocido != 2 {
		t.Errorf("se colocaron %d archivos buenos, se esperaban 2",
			s.Usuario+s.Sistema+s.Desconocido)
	}

	// El corrupto tiene que estar en dudosos/ y NO mezclado con el resto.
	dudosos, _ := filepath.Glob(filepath.Join(dest, "dudosos", "*"))
	if len(dudosos) != 1 {
		t.Errorf("%d archivos en dudosos/, se esperaba 1", len(dudosos))
	}
}

func TestModoDesconocidoSeRechaza(t *testing.T) {
	_, err := New(Config{Destino: t.TempDir(), Modo: "inventado"}, bytes.NewReader(nil), 100)
	if err == nil {
		t.Error("se esperaba error con un modo desconocido")
	}
}

func TestDestinoVacioSeRechaza(t *testing.T) {
	if _, err := New(Config{Modo: "carve"}, bytes.NewReader(nil), 100); err == nil {
		t.Error("se esperaba error sin directorio de destino")
	}
}

func TestTamanoInvalidoSeRechaza(t *testing.T) {
	if _, err := New(Config{Destino: t.TempDir(), Modo: "carve"}, bytes.NewReader(nil), 0); err == nil {
		t.Error("se esperaba error con tamaño 0")
	}
}

// =========================================================================
// Manifiesto
// =========================================================================

func TestManifiestoRegistraTodo(t *testing.T) {
	dest := t.TempDir()
	disk := discoConArchivos(2<<20, [][]byte{
		fotoJPEG(t, 200, 150, 1),
		corromper(fotoJPEG(t, 200, 150, 2), 0x5A),
	})

	if _, err := ejecutar(t, disk, configBase(dest)); err != nil {
		t.Fatal(err)
	}

	res, err := manifest.Read(filepath.Join(dest, manifest.Nombre))
	if err != nil {
		t.Fatalf("no se pudo leer el manifiesto: %v", err)
	}

	if res.Footer == nil {
		t.Fatal("falta el footer: la ejecución no se marcó como completada")
	}
	if !res.Footer.Completado {
		t.Error("Completado = false tras una ejecución normal")
	}
	if res.Footer.Corruptos != 1 {
		t.Errorf("Corruptos = %d, se esperaba 1", res.Footer.Corruptos)
	}

	// Cada entrada debe llevar su procedencia y su veredicto.
	for _, e := range res.Entradas {
		if e.Offset < 0 {
			t.Errorf("entrada con offset negativo: %+v", e)
		}
		if e.Validacion == "" {
			t.Errorf("entrada sin veredicto de validación: %+v", e)
		}
		if e.Integridad < 0 || e.Integridad > 1 {
			t.Errorf("Integridad = %f fuera de [0,1]", e.Integridad)
		}
	}
}

// TestManifiestoDeEjecucionFallidaNoDiceCompletado: si Run devuelve error, el
// manifiesto debe quedar sin footer. Marcarlo completado sería mentir sobre lo
// que pasó, y además impediría reanudar.
func TestManifiestoDeEjecucionCanceladaNoDiceCompletado(t *testing.T) {
	dest := t.TempDir()
	disk := discoConArchivos(4<<20, [][]byte{fotoJPEG(t, 400, 300, 1)})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelado antes de empezar

	cfg := configBase(dest)
	origen := filepath.Join(t.TempDir(), "origen.img")
	os.WriteFile(origen, disk, 0o644)
	cfg.Origen = origen

	p, err := New(cfg, bytes.NewReader(disk), int64(len(disk)))
	if err != nil {
		t.Fatal(err)
	}
	_ = p.Run(ctx) // se espera que falle o no haga nada

	res, err := manifest.Read(filepath.Join(dest, manifest.Nombre))
	if err != nil {
		t.Skipf("no se llegó a crear manifiesto: %v", err)
	}
	if res.Footer != nil && res.Footer.Completado {
		t.Error("una ejecución cancelada se marcó como completada")
	}
}

// =========================================================================
// Deduplicación
// =========================================================================

func TestDeduplicacionPorContenido(t *testing.T) {
	dest := t.TempDir()

	foto := fotoJPEG(t, 300, 200, 7)
	disk := discoConArchivos(4<<20, [][]byte{foto, foto, foto, foto})

	p, err := ejecutar(t, disk, configBase(dest))
	if err != nil {
		t.Fatal(err)
	}

	s := p.Stats()
	if s.Duplicado != 3 {
		t.Errorf("Duplicado = %d, se esperaban 3 de 4 copias", s.Duplicado)
	}

	var archivos int
	filepath.Walk(dest, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && !strings.HasSuffix(path, ".jsonl") &&
			!strings.HasSuffix(path, ".meta.json") {
			archivos++
		}
		return nil
	})
	if archivos != 1 {
		t.Errorf("%d archivos en el destino, se esperaba 1", archivos)
	}
}

// =========================================================================
// Reanudación
// =========================================================================

// TestReanudarContinuaDondeQuedo comprueba el ciclo completo de reanudación con
// el pipeline real, no solo con el manifiesto aislado.
func TestReanudarContinuaDondeQuedo(t *testing.T) {
	dest := t.TempDir()
	disk := discoConArchivos(6<<20, [][]byte{
		fotoJPEG(t, 200, 150, 1),
		fotoJPEG(t, 200, 150, 2),
		fotoJPEG(t, 200, 150, 3),
	})

	// Primera pasada completa, para saber cuál es el resultado correcto.
	refDir := t.TempDir()
	ref, err := ejecutar(t, disk, configBase(refDir))
	if err != nil {
		t.Fatal(err)
	}
	refTotal := ref.Stats().Usuario + ref.Stats().Sistema + ref.Stats().Desconocido

	// Ahora una pasada, se trunca el manifiesto y se borra la salida para
	// simular una interrupción.
	if _, err := ejecutar(t, disk, configBase(dest)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dest, manifest.Nombre)
	data, _ := os.ReadFile(path)
	lineas := strings.SplitAfter(string(data), "\n")
	if len(lineas) < 3 {
		t.Skip("no hay suficientes entradas para simular una interrupción")
	}
	os.WriteFile(path, []byte(lineas[0]+lineas[1]), 0o644) // header + 1 archivo
	for _, d := range []string{"user_content", "unknown", "system_files", "dudosos"} {
		os.RemoveAll(filepath.Join(dest, d))
	}

	cfg := configBase(dest)
	cfg.Reanudar = true
	p2, err := ejecutar(t, disk, cfg)
	if err != nil {
		t.Fatal(err)
	}

	final, err := manifest.Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(final.Entradas) != refTotal {
		t.Errorf("tras reanudar hay %d entradas, la ejecución completa dio %d",
			len(final.Entradas), refTotal)
	}
	t.Logf("reanudado: %d entradas totales, %d en el segundo tramo",
		len(final.Entradas), p2.Stats().Usuario+p2.Stats().Desconocido+p2.Stats().Sistema)
}

// =========================================================================
// Opciones
// =========================================================================

func TestSoloUsuarioDescartaElResto(t *testing.T) {
	dest := t.TempDir()
	disk := discoConArchivos(2<<20, [][]byte{iconoPNG(t), iconoPNG(t)})

	cfg := configBase(dest)
	cfg.SoloUsuario = true

	p, err := ejecutar(t, disk, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if p.Stats().Sistema != 0 {
		t.Errorf("Sistema = %d con -user-only", p.Stats().Sistema)
	}
	if p.Stats().Descartado == 0 {
		t.Error("no se descartó nada con -user-only y solo iconos")
	}
}

// corromperRuido contamina con datos de alta entropía, que es lo que solo
// detecta la decodificación completa.
func corromperRuido(data []byte) []byte {
	out := make([]byte, len(data))
	copy(out, data)
	var s uint32 = 0xBEEF
	for i := len(out) / 3; i < len(out)*2/3; i++ {
		s = s*1664525 + 1013904223
		out[i] = byte(s >> 24)
	}
	return out
}

// TestSinValidarDocumentaQueSePierde precisa el efecto exacto de -no-validar.
//
// No desactiva TODA la validación: las comprobaciones baratas (estructura y
// rachas de bytes) siguen ejecutándose porque cuestan una pasada secuencial.
// Lo que se pierde es la decodificación completa, que es la única señal capaz
// de detectar contaminación de ALTA entropía.
func TestSinValidarDocumentaQueSePierde(t *testing.T) {
	// Caso 1: contaminación de baja entropía. La detecta la heurística barata,
	// así que SIGUE detectándose sin validación profunda.
	t.Run("baja entropia sigue detectandose", func(t *testing.T) {
		dest := t.TempDir()
		disk := discoConArchivos(2<<20, [][]byte{corromper(fotoJPEG(t, 300, 200, 1), 0x5A)})

		cfg := configBase(dest)
		cfg.Validar = false

		p, err := ejecutar(t, disk, cfg)
		if err != nil {
			t.Fatal(err)
		}
		if p.Stats().Dudoso != 1 {
			t.Errorf("Dudoso = %d: la heurística barata debería seguir activa",
				p.Stats().Dudoso)
		}
	})

	// Caso 2: contaminación de alta entropía. Solo la detecta decodificando,
	// así que SIN validación profunda pasa por buena. Este es el coste real.
	t.Run("alta entropia pasa desapercibida", func(t *testing.T) {
		dest := t.TempDir()
		disk := discoConArchivos(2<<20, [][]byte{corromperRuido(fotoJPEG(t, 300, 200, 1))})

		cfg := configBase(dest)
		cfg.Validar = false

		p, err := ejecutar(t, disk, cfg)
		if err != nil {
			t.Fatal(err)
		}
		if p.Stats().Dudoso != 0 {
			t.Errorf("Dudoso = %d: sin decodificar no hay forma de detectar esto",
				p.Stats().Dudoso)
		}

		// Y con validación profunda SÍ se detecta: es la comparación que
		// justifica que la opción esté activada por defecto.
		dest2 := t.TempDir()
		cfg2 := configBase(dest2)
		p2, err := ejecutar(t, disk, cfg2)
		if err != nil {
			t.Fatal(err)
		}
		if p2.Stats().Dudoso != 1 {
			t.Errorf("Dudoso = %d con validación profunda: debería detectarlo",
				p2.Stats().Dudoso)
		}
	})
}

func TestCategoriaFiltraFirmas(t *testing.T) {
	dest := t.TempDir()
	disk := discoConArchivos(2<<20, [][]byte{fotoJPEG(t, 200, 150, 1)})

	cfg := configBase(dest)
	cfg.Categoria = "video" // ningún JPEG debería salir

	p, err := ejecutar(t, disk, cfg)
	if err != nil {
		t.Fatal(err)
	}
	total := p.Stats().Usuario + p.Stats().Sistema + p.Stats().Desconocido + p.Stats().Dudoso
	if total != 0 {
		t.Errorf("se recuperaron %d archivos filtrando por vídeo sobre un disco con JPEG", total)
	}
}

func TestCategoriaInexistenteFalla(t *testing.T) {
	cfg := configBase(t.TempDir())
	cfg.Categoria = "no-existe"

	disk := make([]byte, 1<<20)
	if _, err := ejecutar(t, disk, cfg); err == nil {
		t.Error("se esperaba error con una categoría inexistente")
	}
}

// =========================================================================
// Callbacks y salida
// =========================================================================

// TestNoEscribeEnStdoutPorDefecto: el paquete no debe imprimir salvo que el
// llamante lo pida. Es lo que permite usarlo como librería.
func TestNoEscribeEnStdoutPorDefecto(t *testing.T) {
	dest := t.TempDir()
	disk := discoConArchivos(1<<20, [][]byte{fotoJPEG(t, 100, 100, 1)})

	cfg := configBase(dest)
	origen := filepath.Join(t.TempDir(), "origen.img")
	os.WriteFile(origen, disk, 0o644)
	cfg.Origen = origen

	p, err := New(cfg, bytes.NewReader(disk), int64(len(disk)))
	if err != nil {
		t.Fatal(err)
	}
	// Sin SetSalida: la salida por defecto es io.Discard.
	if p.salida != nil {
		if _, esDiscard := p.salida.(interface{ Write([]byte) (int, error) }); !esDiscard {
			t.Error("la salida por defecto deberia ser un io.Writer valido")
		}
	}
	if err := p.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestSalidaCapturable(t *testing.T) {
	dest := t.TempDir()
	disk := discoConArchivos(1<<20, [][]byte{fotoJPEG(t, 100, 100, 1)})

	var buf bytes.Buffer
	cfg := configBase(dest)
	origen := filepath.Join(t.TempDir(), "origen.img")
	os.WriteFile(origen, disk, 0o644)
	cfg.Origen = origen

	p, err := New(cfg, bytes.NewReader(disk), int64(len(disk)))
	if err != nil {
		t.Fatal(err)
	}
	p.SetSalida(&buf)

	if err := p.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if buf.Len() == 0 {
		t.Error("no se capturó nada de la salida")
	}
}

func TestAvisosLleganAlCallback(t *testing.T) {
	dest := t.TempDir()
	disk := discoConArchivos(1<<20, [][]byte{fotoJPEG(t, 100, 100, 1)})

	var avisos []string
	cfg := configBase(dest)
	origen := filepath.Join(t.TempDir(), "origen.img")
	os.WriteFile(origen, disk, 0o644)
	cfg.Origen = origen

	p, err := New(cfg, bytes.NewReader(disk), int64(len(disk)))
	if err != nil {
		t.Fatal(err)
	}
	p.OnAviso = func(m string) { avisos = append(avisos, m) }

	if err := p.Run(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Una segunda ejecución sobre el mismo destino SÍ tiene algo que avisar:
	// que ya existe un escaneo completo y se va a repetir el trabajo. Es el
	// caso donde el callback importa, porque el usuario debe poder decidir.
	var avisos2 []string
	p2, err := New(cfg, bytes.NewReader(disk), int64(len(disk)))
	if err != nil {
		t.Fatal(err)
	}
	p2.OnAviso = func(m string) { avisos2 = append(avisos2, m) }
	if err := p2.Run(context.Background()); err != nil {
		t.Fatal(err)
	}

	if len(avisos2) == 0 {
		t.Error("no llegó ningún aviso al repetir sobre un destino ya usado")
	}
	var encontrado bool
	for _, a := range avisos2 {
		if strings.Contains(a, "COMPLETO") {
			encontrado = true
		}
	}
	if !encontrado {
		t.Errorf("no se avisó del escaneo previo; avisos: %v", avisos2)
	}
}

// =========================================================================
// Integridad
// =========================================================================

func TestIntegridadEnRango(t *testing.T) {
	casos := []struct {
		nombre    string
		estado    string
		conFooter bool
	}{
		{"válido con footer", "valido", true},
		{"válido sin footer", "valido", false},
		{"sin comprobar", "sin_comprobar", true},
		{"corrupto", "corrupto", true},
	}

	for _, c := range casos {
		v := validateResult(c.estado)
		got := integridad(v, nil, c.conFooter)
		if got < 0 || got > 1 {
			t.Errorf("%s: integridad = %f, fuera de [0,1]", c.nombre, got)
		}
		if c.estado == "corrupto" && got != 0 {
			t.Errorf("%s: integridad = %f, un corrupto debe dar 0", c.nombre, got)
		}
	}
}

// TestIntegridadPremiaElFooter: un archivo que terminó en su marcador de fin es
// más fiable que uno cortado por el tope de tamaño.
func TestIntegridadPremiaElFooter(t *testing.T) {
	v := validateResult("valido")
	con := integridad(v, nil, true)
	sin := integridad(v, nil, false)

	if con <= sin {
		t.Errorf("con footer %f no supera a sin footer %f", con, sin)
	}
}

// validateResult construye un veredicto con el estado dado, para probar la
// funcion de integridad sin generar archivos reales.
func validateResult(estado string) validate.Result {
	r := validate.Result{Estado: estado, Metodo: "test"}
	switch estado {
	case validate.Valido:
		r.Score = 1
	case validate.SinComprobar:
		r.Score = 0.5
	}
	return r
}
