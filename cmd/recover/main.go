// Command recover recupera archivos de discos dañados o formateados.
//
// Dos estrategias, en este orden:
//
//	list   Lee la estructura del sistema de archivos aunque esté parcialmente
//	       dañada. Conserva nombres originales y carpetas.
//	carve  Busca firmas mágicas byte a byte. Funciona sin sistema de archivos,
//	       pero pierde los nombres.
//
// El modo auto intenta list y cae a carve si no reconoce el sistema de archivos.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/edcamero/disk-recover/internal/blockdev"
	"github.com/edcamero/disk-recover/internal/carver"
	"github.com/edcamero/disk-recover/internal/classifier"
	"github.com/edcamero/disk-recover/internal/filesystem"
	"github.com/edcamero/disk-recover/internal/manifest"
	"github.com/edcamero/disk-recover/internal/namerecovery"
	"github.com/edcamero/disk-recover/internal/output"
	"github.com/edcamero/disk-recover/internal/scanner"
	"github.com/edcamero/disk-recover/internal/signatures"
	"github.com/edcamero/disk-recover/internal/validate"
)

// systemConfidence es la confianza mínima para mandar algo a system_files.
//
// La lógica anterior estaba invertida: enviaba a "system" lo clasificado con
// confianza BAJA (< 0.3) y dejaba en "unknown" lo identificado con confianza
// alta. Ahora system_files solo recibe lo que sabemos que no es del usuario, y
// la franja dudosa va a unknown/, que es lo que hay que revisar a mano.
const systemConfidence = 0.5

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "\n❌ %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	device := flag.String("src", "", "dispositivo o imagen de disco (ej: /dev/sdb1 o backup.img)")
	out := flag.String("out", "./recovered", "directorio de salida")
	mode := flag.String("mode", "auto", "modo de operación: auto, list, carve")
	classify := flag.Bool("classify", true, "activar clasificación inteligente (usuario vs sistema)")
	userOnly := flag.Bool("user-only", false, "solo conservar contenido de usuario")
	sigFile := flag.String("sigfile", "", "archivo de firmas adicional (.sig)")
	category := flag.String("category", "", "filtrar por categoría: image, video, document, archive")
	noValidar := flag.Bool("no-validar", false,
		"desactivar la validacion profunda (mas rapido, pero no distingue integro de corrupto)")
	reanudar := flag.Bool("reanudar", false,
		"continuar un escaneo interrumpido en lugar de empezar de cero")
	minFree := flag.Int64("min-libre", 1<<30,
		"espacio libre minimo exigido en el destino, en bytes")
	sector := flag.Int64("sector", blockdev.DefaultSectorSize,
		"tamaño de sector para dispositivos en crudo (512 o 4096)")
	flag.Parse()

	if *device == "" {
		return fmt.Errorf("debes especificar -src /dev/sdX o -src imagen.img")
	}
	switch *mode {
	case "auto", "list", "carve":
	default:
		return fmt.Errorf("modo desconocido %q: usa auto, list o carve", *mode)
	}

	// Una letra de unidad suelta ("D:") no son los bytes del disco sino un
	// directorio. Se traduce a la ruta de volumen en crudo, que es lo único que
	// tiene sentido para esta herramienta.
	devicePath := *device
	if normalized, changed := blockdev.NormalizeSource(devicePath); changed {
		fmt.Printf("ℹ️  %s es un directorio, no un volumen. Usando %s\n\n", devicePath, normalized)
		devicePath = normalized
	}

	// 1. Abrir el origen en solo lectura. Nunca se escribe en él.
	src, err := os.Open(devicePath)
	if err != nil {
		return openError(devicePath, err)
	}
	defer src.Close()

	// Un directorio no se puede escanear: su ReadAt falla con "Incorrect
	// function" y su tamaño no significa nada. Detectarlo aquí evita un fallo
	// incomprensible más adelante.
	if info, statErr := src.Stat(); statErr == nil && info.IsDir() {
		return fmt.Errorf(
			"%s es un directorio, no un disco ni una imagen.\n"+
				"   Para un volumen entero usa la ruta en crudo (ej: %s)\n"+
				"   Para una imagen, indica el archivo (ej: %s\\backup.img)",
			devicePath, rawDeviceHint(devicePath), strings.TrimRight(devicePath, `\/`))
	}

	size, err := blockdev.DeviceSize(src)
	if err != nil {
		return err
	}

	// Sobre un dispositivo en crudo, las lecturas tienen que ir alineadas a
	// sector. El carver no lo cumple por sí solo: al extraer un archivo lee
	// exactamente sus bytes, y un JPEG rara vez mide un múltiplo de 512. En
	// Windows esa última lectura desalineada devuelve ERROR_INVALID_PARAMETER,
	// así que sin este envoltorio no se recuperaría ni un archivo.
	var reader io.ReaderAt = src
	if blockdev.IsRawDevice(devicePath) {
		// Si el usuario no forzó un valor, preguntarle al propio dispositivo.
		// Un disco 4Kn nativo rechaza cualquier lectura alineada a 512.
		effectiveSector := *sector
		if !sectorFlagSet() {
			effectiveSector = blockdev.DetectSectorSize(src)
		}
		reader = blockdev.NewAligned(src, effectiveSector, size)
		fmt.Printf("💽 Dispositivo en crudo: lecturas alineadas a %d bytes\n", effectiveSector)
	}

	// 2. Comprobar que no vamos a escribir sobre el propio disco que leemos.
	// Se hace ANTES de crear ningún directorio.
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return fmt.Errorf("no se pudo crear %s: %w", *out, err)
	}
	if same, err := sameDeviceCheck(devicePath, *out); err != nil {
		return err
	} else if same {
		return fmt.Errorf(
			"el destino %q está en el mismo dispositivo que el origen %q; "+
				"nunca escribas en el disco que intentas recuperar", *out, devicePath)
	}

	fmt.Printf("🔍 Analizando: %s (%.2f GB)\n", devicePath, float64(size)/(1<<30))
	fmt.Printf("📁 Salida: %s\n", *out)
	fmt.Printf("⚙️  Modo: %s | Clasificar: %v | Solo usuario: %v\n\n", *mode, *classify, *userOnly)

	// 3. Cancelación ordenada con Ctrl+C. Un carving de 2 TB dura horas.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 4. Comprobar que hay sitio ANTES de empezar. Un escaneo de horas que
	// llena el destino a mitad falla archivo a archivo y termina con
	// estadísticas engañosas; avisar ahora convierte eso en algo accionable.
	if err := comprobarEspacio(*out, size, *minFree); err != nil {
		return err
	}

	app := &app{
		out:        *out,
		userDir:    filepath.Join(*out, "user_content"),
		systemDir:  filepath.Join(*out, "system_files"),
		unknownDir: filepath.Join(*out, "unknown"),
		dudososDir: filepath.Join(*out, "dudosos"),
		staging:    filepath.Join(*out, ".staging"),
		userOnly:   *userOnly,
		stats:      map[string]int{},
		validOpts:  validate.Options{Profundo: !*noValidar, MaxPixeles: validate.DefaultMaxPixeles},
		vistos:     map[string]bool{},
	}
	if *classify {
		app.classifier = classifier.New()
		app.resolver = namerecovery.NewResolver(reader)
	}

	if err := os.MkdirAll(app.staging, 0o755); err != nil {
		return fmt.Errorf("no se pudo crear el directorio temporal: %w", err)
	}
	defer os.Remove(app.staging) // solo funciona si quedó vacío, que es lo deseable

	// 5. Manifiesto. Es lo que hace el resultado trazable y reproducible, y lo
	// que permite reanudar un escaneo interrumpido.
	man, desde, err := abrirManifiesto(*out, devicePath, *mode, size, *reanudar, app)
	if err != nil {
		return err
	}
	app.manifest = man

	// completado se pone a true solo si se llega al final por las buenas.
	completado := false
	defer func() {
		if completado {
			man.Close(true, app.ilegibles)
		} else {
			// Interrupción o error: el manifiesto queda sin footer, que es la
			// marca de "esto no terminó" y la señal para poder reanudar.
			man.Abort()
		}
	}()

	if *noValidar {
		fmt.Println("⚠️  Validación profunda DESACTIVADA: no se podrá distinguir")
		fmt.Println("   un archivo íntegro de uno corrupto.")
	}

	// 6. FASE LIST
	listOK := false
	if *mode == "auto" || *mode == "list" {
		listOK, err = app.runList(ctx, reader, size)
		if err != nil {
			return err
		}
	}

	if *mode == "list" {
		completado = true
		app.printStats()
		return nil
	}

	// 7. FASE CARVE: fallback si list no dio nada, o si se pidió explícitamente.
	if !listOK || *mode == "carve" {
		if err := app.runCarve(ctx, reader, size, devicePath, *sigFile, *category, desde); err != nil {
			return err
		}
	}

	completado = true
	fmt.Println("\n" + strings.Repeat("=", 52))
	app.printStats()
	fmt.Printf("✅ Proceso completado. Revisa: %s\n", *out)
	fmt.Printf("📄 Manifiesto: %s\n", filepath.Join(*out, manifest.Nombre))
	return nil
}

// herramienta identifica esta versión en el manifiesto, para poder comparar
// resultados entre versiones del programa.
const herramienta = "disk-recover"

// abrirManifiesto crea uno nuevo o continúa el de un escaneo interrumpido.
//
// Devuelve también el offset desde el que arrancar: repetir el trabajo ya hecho
// sobre un disco de 2 TB cuesta horas, y es lo que convierte una interrupción en
// una molestia en lugar de en una pérdida.
func abrirManifiesto(destDir, origen, modo string, size int64, reanudar bool, a *app) (*manifest.Writer, int64, error) {
	path := filepath.Join(destDir, manifest.Nombre)

	previo, err := manifest.Read(path)
	switch {
	case err != nil:
		// No hay manifiesto previo, o es ilegible: se empieza de cero.
	case !previo.Reanudable():
		fmt.Printf("ℹ️  Ya existe un escaneo COMPLETO en %s.\n", destDir)
		fmt.Printf("   Se creará un manifiesto nuevo y se repetirá el trabajo.\n\n")
	case previo.Header.Origen != origen:
		fmt.Printf("⚠️  El manifiesto de %s corresponde a otro origen (%q).\n",
			destDir, previo.Header.Origen)
		fmt.Printf("   No se reanuda: se empieza de cero.\n\n")
	case !reanudar:
		fmt.Printf("ℹ️  Hay un escaneo INTERRUMPIDO en %s con %d archivos ya recuperados.\n",
			destDir, len(previo.Entradas))
		fmt.Printf("   Usa -reanudar para continuar desde el byte %d en lugar de empezar de cero.\n\n",
			previo.UltimoOfset)
	default:
		// Reanudación efectiva.
		w, err := manifest.Append(destDir, previo)
		if err != nil {
			return nil, 0, err
		}
		a.vistos = previo.Hashes()

		fmt.Printf("▶️  Reanudando: %d archivos ya recuperados, se continúa desde %.2f GB (%.1f%%).\n\n",
			len(previo.Entradas),
			float64(previo.UltimoOfset)/(1<<30),
			float64(previo.UltimoOfset)*100/float64(size))
		return w, previo.UltimoOfset, nil
	}

	w, err := manifest.Create(destDir, manifest.Header{
		Origen:      origen,
		OrigenBytes: size,
		Destino:     destDir,
		Modo:        modo,
		Herramienta: herramienta,
	})
	return w, 0, err
}

// extensionAFormato traduce la extensión al nombre de firma que usa el
// validador.
//
// Hace falta en modo list: ahí el archivo viene del sistema de archivos y no de
// una firma mágica, así que no se sabe su formato. Lo único disponible es el
// nombre, y eso basta para elegir validador — si la extensión miente, el
// validador lo detectará y el archivo acabará en dudosos/, que es el
// comportamiento correcto.
var extensionAFormato = map[string]string{
	".jpg": "jpeg", ".jpeg": "jpeg", ".jpe": "jpeg",
	".png": "png",
	".gif": "gif",
	".pdf": "pdf",
	".zip": "zip", ".docx": "zip", ".xlsx": "zip", ".pptx": "zip",
}

// formatoPorExtension devuelve el formato deducible del nombre, o "" si no se
// reconoce. Cadena vacía significa "no validar", no "válido".
func formatoPorExtension(nombre string) string {
	return extensionAFormato[strings.ToLower(filepath.Ext(nombre))]
}

// comprobarEspacio verifica que el destino tiene sitio suficiente.
//
// La estimación es deliberadamente conservadora: en el peor caso el origen está
// lleno de archivos recuperables, así que hace falta tanto espacio como tenga el
// origen. Como eso casi nunca se cumple, se avisa en vez de abortar salvo que el
// margen sea claramente insuficiente.
func comprobarEspacio(destDir string, origenBytes, minFree int64) error {
	libre, err := blockdev.FreeSpace(destDir)
	if err != nil {
		// No poder consultarlo no debe impedir trabajar, pero sí decirlo.
		fmt.Printf("⚠️  No se pudo comprobar el espacio libre en %s: %v\n", destDir, err)
		return nil
	}

	if libre < minFree {
		return fmt.Errorf(
			"solo hay %.2f GB libres en %s y se exigen al menos %.2f GB.\n"+
				"   Libera espacio o elige otro destino con -out",
			float64(libre)/(1<<30), destDir, float64(minFree)/(1<<30))
	}

	if libre < origenBytes {
		fmt.Printf("⚠️  El destino tiene %.2f GB libres y el origen mide %.2f GB.\n",
			float64(libre)/(1<<30), float64(origenBytes)/(1<<30))
		fmt.Printf("   Suele bastar, porque no todo el disco es contenido recuperable,\n")
		fmt.Printf("   pero el escaneo se detendrá si se agota.\n\n")
	}
	return nil
}

// app agrupa el estado compartido entre las dos fases.
type app struct {
	out        string
	userDir    string
	systemDir  string
	unknownDir string
	ilegibles  []manifest.RegionJSON
	dudososDir string
	staging    string

	classifier *classifier.Classifier
	resolver   *namerecovery.Resolver
	manifest   *manifest.Writer
	validOpts  validate.Options
	userOnly   bool
	stats      map[string]int

	// vistos son los SHA256 ya recuperados, para no duplicar. Se siembra desde
	// el manifiesto al reanudar, asi que la deduplicacion cruza ejecuciones.
	vistos map[string]bool
}

// =========================================================================
// Modo LIST
// =========================================================================

func (a *app) runList(ctx context.Context, src io.ReaderAt, size int64) (bool, error) {
	fmt.Println("📂 Intentando leer la estructura del sistema de archivos...")

	lister := filesystem.NewLister(src, size)
	fsType := lister.FSType()
	if fsType == "unknown" {
		fmt.Println("⚠️  No se reconoció un sistema de archivos válido.")
		return false, nil
	}

	fmt.Printf("✅ Sistema de archivos detectado: %s\n", fsType)

	entries, err := lister.List()
	if err != nil || len(entries) == 0 {
		if err != nil {
			fmt.Printf("⚠️  %v\n", err)
		} else {
			fmt.Println("⚠️  FS detectado, pero no se pudieron leer entradas válidas.")
		}
		return false, nil
	}
	fmt.Printf("📋 %d entradas encontradas. Extrayendo...\n", len(entries))

	extractor := filesystem.NewExtractor(src)
	recuperados := 0

	for _, entry := range entries {
		select {
		case <-ctx.Done():
			fmt.Println("\n⚠️  Cancelado por el usuario.")
			return recuperados > 0, nil
		default:
		}

		if entry.IsDir || entry.Size <= 0 || !entry.Recoverable {
			continue
		}

		// El nombre viene del disco auditado: se sanea antes de tocar el
		// sistema de archivos local.
		safeName := output.SanitizeFilename(entry.Name)
		if safeName == "" {
			continue
		}

		stagePath := filepath.Join(a.staging, fmt.Sprintf("%d_%s", entry.Offset, safeName))
		if _, err := extractor.ExtractTo(entry, stagePath); err != nil {
			os.Remove(stagePath)
			continue
		}

		// En modo list conservamos la carpeta original: es información que el
		// carving no puede recuperar y tiene valor por sí misma.
		relDir := output.SanitizeRelPath(filepath.Dir(entry.Path))
		a.process(recoveredFile{
			stagePath: stagePath,
			nombre:    safeName,
			relDir:    relDir,
			offset:    entry.Offset,
			size:      entry.Size,
			formato:   formatoPorExtension(safeName),
			metodo:    "fs",
			conFooter: true, // el FS declaró el tamaño exacto
		})
		recuperados++
	}

	fmt.Printf("✅ Extracción por sistema de archivos completada (%d archivos).\n", recuperados)
	return recuperados > 0, nil
}

// =========================================================================
// Modo CARVE
// =========================================================================

func (a *app) runCarve(ctx context.Context, src io.ReaderAt, size int64, devicePath, sigFile, category string, desde int64) error {
	fmt.Println("\n🔪 Iniciando file carving (búsqueda por firmas mágicas)...")

	reg, err := buildRegistry(sigFile, category)
	if err != nil {
		return err
	}
	fmt.Printf("🔎 %d firmas activas.\n", reg.Count())

	writer, err := output.NewSafeWriter(a.staging, devicePath)
	if err != nil {
		return err
	}

	c := carver.New(src, size, writer, reg)
	if desde > 0 {
		c.SetStartOffset(desde)
	}
	c.SetCancelChannel(ctx.Done())
	c.SetProgressCallback(func(p scanner.Progress) {
		fmt.Printf("\r   %.1f%%  %.1f MB/s  ETA %s      ", p.Percent, p.SpeedMBps, p.ETA.Round(1e9))
	})

	results, err := c.Run()

	// Recoger las regiones ilegibles para el manifiesto: saber QUE no se pudo
	// leer es tan util como saber que si.
	for _, r := range c.Ilegibles() {
		a.ilegibles = append(a.ilegibles, manifest.RegionJSON{Offset: r.Offset, Length: r.Length})
	}
	fmt.Println()
	if err != nil && len(results) == 0 {
		return fmt.Errorf("carving fallido: %w", err)
	}
	if err != nil {
		fmt.Printf("⚠️  El escaneo terminó antes de tiempo: %v\n", err)
	}

	fmt.Printf("🔍 Carving finalizado. Procesando %d archivos...\n", len(results))

	for _, r := range results {
		// Intentar recuperar el nombre original. Fallar es lo normal.
		name := filepath.Base(r.Path)
		if a.resolver != nil {
			if original, err := a.resolver.Resolve(r.Path, r.Offset, r.Size); err == nil && original != "" {
				if safe := namerecovery.Sanitize(original); safe != "" {
					name = safe
				}
			}
		}
		a.process(recoveredFile{
			stagePath: r.Path,
			nombre:    name,
			offset:    r.Offset,
			size:      r.Size,
			formato:   r.Type,
			sha256:    r.SHA256,
			conFooter: r.FooterHallado,
			metodo:    "carve",
		})
	}

	return nil
}

// buildRegistry monta el registro de firmas: las de serie, más las del archivo
// del usuario, filtradas por categoría si se pidió.
func buildRegistry(sigFile, category string) (*signatures.Registry, error) {
	reg := signatures.DefaultRegistry()

	if sigFile != "" {
		if err := reg.LoadFromFile(sigFile); err != nil {
			return nil, fmt.Errorf("no se pudieron cargar las firmas de %s: %w", sigFile, err)
		}
	}

	if category == "" {
		return reg, nil
	}

	filtered := signatures.NewRegistry()
	for _, sig := range reg.FilterByCategory(category) {
		if err := filtered.Register(sig); err != nil {
			return nil, fmt.Errorf("firma %q inválida: %w", sig.Name, err)
		}
	}
	if filtered.Count() == 0 {
		return nil, fmt.Errorf("ninguna firma en la categoría %q", category)
	}
	return filtered, nil
}

// =========================================================================
// Clasificación y colocación final
// =========================================================================

// recovered describe un archivo extraído a staging, antes de decidir su destino.
type recoveredFile struct {
	stagePath string
	nombre    string
	relDir    string
	offset    int64
	size      int64
	formato   string // firma que lo identificó, "" si vino del FS
	sha256    string
	conFooter bool
	metodo    string // "carve" o "fs"
}

// process valida, clasifica y coloca un archivo ya extraído.
//
// El orden importa: la VALIDACIÓN va primero. Un archivo corrupto no se
// clasifica ni se mezcla con los buenos, porque el problema más grave de esta
// herramienta no era recuperar poco, sino entregar archivos corruptos
// indistinguibles de los correctos.
func (a *app) process(r recoveredFile) {
	entry := manifest.Entry{
		Offset: r.offset, Size: r.size, Metodo: r.metodo,
		Formato: r.formato, SHA256: r.sha256, FooterHallado: r.conFooter,
	}

	// 0. Deduplicar por contenido. El SHA256 ya se calculó al escribir, así que
	// esto no cuesta ninguna lectura extra. Sin ello, un archivo presente diez
	// veces en el disco produce diez copias en la salida.
	if r.sha256 != "" && a.vistos != nil {
		if a.vistos[r.sha256] {
			os.Remove(r.stagePath)
			a.stats["duplicado"]++
			entry.Descarte = "duplicado por contenido (SHA256 ya recuperado)"
			a.anotar(entry)
			return
		}
		a.vistos[r.sha256] = true
	}

	// 1. Validar la estructura interna.
	val := validate.Result{Estado: validate.SinComprobar, Score: 0.5, Metodo: "ninguno"}
	if r.formato != "" {
		val = validate.File(r.stagePath, r.formato, a.validOpts)
	}
	entry.Validacion = val.Estado
	entry.ValidMetodo = val.Metodo
	entry.ValidMotivo = val.Motivo

	// 2. Clasificar. Un archivo corrupto no se clasifica: la heurística lee
	// EXIF y dimensiones, y sobre datos contaminados produce respuestas sin
	// sentido que además irían al .meta.json como si fueran ciertas.
	var verdict *classifier.Result
	if a.classifier != nil && val.Estado != validate.Corrupto {
		if res, err := a.classifier.Classify(r.stagePath, r.offset); err == nil {
			verdict = res
			entry.Categoria = res.Category
			entry.EsUsuario = res.IsUserContent
		}
	}

	entry.Integridad = integridad(val, verdict, r.conFooter)

	// 3. Decidir destino.
	categoria, targetBase := a.destino(val, verdict)

	// Con -user-only no llegamos a escribir lo que vamos a descartar.
	if a.userOnly && categoria != "user" {
		os.Remove(r.stagePath)
		a.stats["descartado"]++
		entry.Descarte = "solo se conserva contenido de usuario"
		a.anotar(entry)
		return
	}

	targetDir := targetBase
	if r.relDir != "" {
		targetDir = filepath.Join(targetBase, r.relDir)
	}

	finalPath, err := output.Place(r.stagePath, targetDir, r.nombre)
	if err != nil {
		fmt.Printf("\n⚠️  No se pudo colocar %s: %v\n", filepath.Base(r.stagePath), err)
		os.Remove(r.stagePath)
		a.stats["error"]++
		entry.Descarte = "error al colocar: " + err.Error()
		a.anotar(entry)
		return
	}
	entry.Destino = finalPath

	// Los metadatos se escriben DESPUÉS de que el archivo esté en su sitio: así
	// el directorio existe con seguridad y el nombre ya es el definitivo.
	if verdict != nil && categoria == "user" {
		writeMeta(finalPath, verdict)
	}

	a.stats[categoria]++
	a.anotar(entry)

	switch categoria {
	case "user":
		fmt.Printf("  ✅ [%s/%s] %s (integridad %.2f)\n",
			categoria, verdict.Category, filepath.Base(finalPath), entry.Integridad)
	case "dudoso":
		fmt.Printf("  ⚠️  [dudoso] %s — %s\n", filepath.Base(finalPath), val.Motivo)
	}
}

// destino decide la carpeta según el veredicto de integridad y la clasificación.
//
// Lo corrupto va aparte SIEMPRE, por encima de cualquier otra consideración:
// mezclarlo con lo bueno es exactamente el fallo que esta capa viene a resolver.
func (a *app) destino(val validate.Result, verdict *classifier.Result) (string, string) {
	if val.Estado == validate.Corrupto {
		return "dudoso", a.dudososDir
	}
	if verdict == nil {
		return "unknown", a.unknownDir
	}
	switch {
	case verdict.IsUserContent:
		return "user", filepath.Join(a.userDir, verdict.Category)
	case verdict.Confidence >= systemConfidence:
		return "system", a.systemDir
	}
	return "unknown", a.unknownDir
}

// integridad combina las señales disponibles en una puntuación de 0 a 1.
//
// Es distinta de classifier.Confidence, que responde "¿es del usuario o del
// sistema?". Esta responde "¿está íntegro?", que es la pregunta que el usuario
// necesita para saber de qué archivos puede fiarse.
func integridad(val validate.Result, verdict *classifier.Result, conFooter bool) float64 {
	if val.Estado == validate.Corrupto {
		return 0
	}

	score := 0.0

	// Validación estructural: la señal de más peso, es la única que mira dentro.
	switch val.Estado {
	case validate.Valido:
		score += 0.60
	case validate.SinComprobar:
		score += 0.30 * val.Score / 0.5 // proporcional a lo que sí se comprobó
	}

	// Footer encontrado: el archivo terminó donde decía, no en un tope arbitrario.
	if conFooter {
		score += 0.25
	}

	// Metadatos coherentes: si el EXIF se parseó y las dimensiones son
	// plausibles, el principio del archivo está intacto.
	if verdict != nil {
		if verdict.HasEXIF {
			score += 0.10
		}
		if verdict.Width > 0 && verdict.Height > 0 {
			score += 0.05
		}
	}

	if score > 1 {
		score = 1
	}
	return score
}

// anotar registra la entrada en el manifiesto, si lo hay.
func (a *app) anotar(e manifest.Entry) {
	if a.manifest == nil {
		return
	}
	if err := a.manifest.Add(e); err != nil {
		fmt.Printf("\n⚠️  No se pudo anotar en el manifiesto: %v\n", err)
	}
}

func writeMeta(finalPath string, verdict *classifier.Result) {
	data, err := json.MarshalIndent(verdict, "", "  ")
	if err != nil {
		return
	}
	if err := os.WriteFile(finalPath+".meta.json", data, 0o644); err != nil {
		fmt.Printf("\n⚠️  No se pudieron guardar los metadatos de %s: %v\n",
			filepath.Base(finalPath), err)
	}
}

func (a *app) printStats() {
	fmt.Println("📊 ESTADÍSTICAS FINALES:")
	fmt.Printf("   📸 Contenido de usuario:      %d\n", a.stats["user"])
	fmt.Printf("   ⚙️  Archivos de sistema:       %d\n", a.stats["system"])
	fmt.Printf("   ❓ Sin clasificar:            %d\n", a.stats["unknown"])
	if n := a.stats["dudoso"]; n > 0 {
		fmt.Printf("   ⚠️  Corruptos (en dudosos/):   %d\n", n)
		fmt.Printf("      Estos archivos NO superaron la validación: su contenido\n")
		fmt.Printf("      no es coherente aunque tengan la forma de su formato.\n")
	}
	if n := a.stats["duplicado"]; n > 0 {
		fmt.Printf("   ♊ Duplicados omitidos:        %d\n", n)
	}
	if n := a.stats["descartado"]; n > 0 {
		fmt.Printf("   🗑️  Descartados (-user-only): %d\n", n)
	}
	if n := a.stats["error"]; n > 0 {
		fmt.Printf("   ⚠️  Errores al guardar:       %d\n", n)
	}
}

// =========================================================================
// sectorFlagSet indica si el usuario pasó -sector explícitamente. Sin esto no
// se puede distinguir "no lo indicó" de "pidió justo el valor por defecto", y
// la autodetección pisaría una elección deliberada.
func sectorFlagSet() bool {
	set := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "sector" {
			set = true
		}
	})
	return set
}

// openError convierte el fallo de os.Open en algo accionable.
//
// "Access is denied" a secas no le dice al usuario que el problema es de
// permisos y no del disco, que es la conclusión a la que se llega solo cuando ya
// se ha perdido un rato.
func openError(path string, err error) error {
	if os.IsPermission(err) {
		if runtime.GOOS == "windows" {
			return fmt.Errorf(
				"acceso denegado a %s.\n"+
					"   Leer un disco en crudo requiere permisos de Administrador:\n"+
					"   abre PowerShell con «Ejecutar como administrador» y repite el comando", path)
		}
		return fmt.Errorf(
			"acceso denegado a %s.\n"+
				"   Leer un dispositivo de bloque requiere privilegios: prueba con sudo", path)
	}

	if os.IsNotExist(err) && blockdev.IsRawDevice(path) {
		return fmt.Errorf(
			"no existe el dispositivo %s.\n"+
				"   Comprueba la letra de unidad o el número de disco (%s)", path, listDevicesHint())
	}

	return fmt.Errorf("no se pudo abrir %s: %w", path, err)
}

// rawDeviceHint sugiere la ruta en crudo correspondiente a la ruta dada.
func rawDeviceHint(path string) string {
	if runtime.GOOS != "windows" {
		return "/dev/sdb1"
	}
	if vol := filepath.VolumeName(path); vol != "" {
		return `\\.\` + vol
	}
	return `\\.\D:`
}

// listDevicesHint indica cómo enumerar los discos disponibles.
func listDevicesHint() string {
	if runtime.GOOS == "windows" {
		return "en PowerShell: Get-Disk, o Get-Volume para las letras"
	}
	return "lsblk"
}

// sameDeviceCheck reutiliza la validación de output creando un SafeWriter de
// usar y tirar: si el destino está en el disco de origen, falla aquí.
func sameDeviceCheck(devicePath, outDir string) (bool, error) {
	if _, err := output.NewSafeWriter(outDir, devicePath); err != nil {
		if strings.Contains(err.Error(), "ERROR DE SEGURIDAD") {
			return true, nil
		}
		return false, err
	}
	return false, nil
}
