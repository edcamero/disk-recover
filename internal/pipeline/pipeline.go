// Package pipeline orquesta la recuperación: detecta el sistema de archivos,
// extrae, valida, clasifica y coloca cada archivo, dejando constancia en el
// manifiesto.
//
// Existe separado del comando por una razón concreta: mientras vivió dentro de
// cmd/recover, eran 800 líneas con 0 % de cobertura. Aquí se puede ejercitar el
// flujo completo contra un io.ReaderAt en memoria, sin disco ni privilegios.
//
// El comando conserva lo que de verdad le corresponde: banderas, señales,
// apertura del dispositivo y presentación.
package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

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

// Config reúne todo lo que decide el comportamiento de una ejecución.
type Config struct {
	// Origen es la ruta del dispositivo o imagen, YA normalizada por el
	// llamante (ver blockdev.NormalizeSource).
	Origen  string
	Destino string
	Modo    string // auto | list | carve

	Clasificar  bool
	SoloUsuario bool
	Validar     bool
	Reanudar    bool

	SigFile   string
	Categoria string
	MinLibre  int64
}

// Stats es el recuento de una ejecución.
type Stats struct {
	Usuario     int
	Sistema     int
	Desconocido int
	Dudoso      int
	Duplicado   int
	Descartado  int
	Error       int
}

// Herramienta identifica esta version en el manifiesto, para poder comparar
// resultados entre versiones del programa.
const herramienta = "disk-recover"

// Progreso describe el avance del escaneo. Es un alias del tipo del scanner
// para que el llamante no tenga que importarlo.
type Progreso = scanner.Progress

// Pipeline ejecuta una recuperación completa.
type Pipeline struct {
	cfg  Config
	src  io.ReaderAt
	size int64

	userDir    string
	systemDir  string
	unknownDir string
	dudososDir string
	staging    string

	classifier *classifier.Classifier
	resolver   *namerecovery.Resolver
	manifest   *manifest.Writer
	validOpts  validate.Options

	stats     Stats
	vistos    map[string]bool
	ilegibles []manifest.RegionJSON
	desde     int64

	// OnProgreso, si se define, recibe el avance del carving.
	OnProgreso func(Progreso)
	// OnArchivo, si se define, se llama por cada archivo colocado.
	OnArchivo func(categoria, ruta string, integridad float64, motivo string)
	// salida recibe el texto legible del progreso. Por defecto se descarta, de
	// modo que el paquete no escribe en stdout salvo que el llamante lo pida:
	// asi los tests pueden ejercitar el flujo completo en silencio, o capturarlo.
	salida io.Writer

	// OnAviso recibe mensajes informativos que el comando puede presentar.
	OnAviso func(string)
}

// New prepara una ejecución. No escribe nada todavía salvo los directorios.
func New(cfg Config, src io.ReaderAt, size int64) (*Pipeline, error) {
	if cfg.Destino == "" {
		return nil, fmt.Errorf("pipeline: se requiere un directorio de destino")
	}
	if size <= 0 {
		return nil, fmt.Errorf("pipeline: tamaño de origen inválido: %d", size)
	}
	switch cfg.Modo {
	case "auto", "list", "carve":
	default:
		return nil, fmt.Errorf("pipeline: modo desconocido %q", cfg.Modo)
	}

	p := &Pipeline{
		cfg:        cfg,
		src:        src,
		size:       size,
		userDir:    filepath.Join(cfg.Destino, "user_content"),
		systemDir:  filepath.Join(cfg.Destino, "system_files"),
		unknownDir: filepath.Join(cfg.Destino, "unknown"),
		dudososDir: filepath.Join(cfg.Destino, "dudosos"),
		staging:    filepath.Join(cfg.Destino, ".staging"),
		vistos:     map[string]bool{},
		validOpts:  validate.Options{Profundo: cfg.Validar, MaxPixeles: validate.DefaultMaxPixeles},
		salida:     io.Discard,
	}
	if cfg.Clasificar {
		p.classifier = classifier.New()
		p.resolver = namerecovery.NewResolver(src)
	}
	return p, nil
}

// Stats devuelve el recuento actual.
func (p *Pipeline) Stats() Stats { return p.stats }

// Run ejecuta la recuperación completa.
func (p *Pipeline) Run(ctx context.Context) error {
	if err := ComprobarEspacio(p.cfg.Destino, p.size, p.cfg.MinLibre, p.aviso); err != nil {
		return err
	}
	if err := os.MkdirAll(p.staging, 0o755); err != nil {
		return fmt.Errorf("no se pudo crear el directorio temporal: %w", err)
	}
	defer os.Remove(p.staging) // solo funciona si quedó vacío, que es lo deseable

	man, desde, err := p.abrirManifiesto()
	if err != nil {
		return err
	}
	p.manifest = man
	p.desde = desde

	completado := false
	defer func() {
		if completado {
			man.Close(true, p.ilegibles)
		} else {
			// Interrupción o error: el manifiesto queda sin footer, que es la
			// marca de "esto no terminó" y la señal para poder reanudar.
			man.Abort()
		}
	}()

	// FASE LIST
	listOK := false
	if p.cfg.Modo == "auto" || p.cfg.Modo == "list" {
		listOK, err = p.runList(ctx)
		if err != nil {
			return err
		}
	}

	if p.cfg.Modo == "list" {
		completado = true
		return nil
	}

	// FASE CARVE: fallback si list no dio nada, o si se pidió explícitamente.
	if !listOK || p.cfg.Modo == "carve" {
		if err := p.runCarve(ctx); err != nil {
			return err
		}
	}

	completado = true
	return nil
}

func (p *Pipeline) aviso(msg string) {
	if p.OnAviso != nil {
		p.OnAviso(msg)
	}
}

// abrirManifiesto crea uno nuevo o continúa el de un escaneo interrumpido.
//
// Devuelve también el offset desde el que arrancar: repetir el trabajo ya hecho
// sobre un disco de 2 TB cuesta horas, y es lo que convierte una interrupción en
// una molestia en lugar de en una pérdida.
func (p *Pipeline) abrirManifiesto() (*manifest.Writer, int64, error) {
	destDir, origen, size := p.cfg.Destino, p.cfg.Origen, p.size
	path := filepath.Join(destDir, manifest.Nombre)

	previo, err := manifest.Read(path)
	switch {
	case err != nil:
		// No hay manifiesto previo, o es ilegible: se empieza de cero.
	case !previo.Reanudable():
		p.aviso(fmt.Sprintf("ya existe un escaneo COMPLETO en %s; "+
			"se creará un manifiesto nuevo y se repetirá el trabajo", destDir))
	case previo.Header.Origen != origen:
		p.aviso(fmt.Sprintf("el manifiesto de %s corresponde a otro origen (%q); "+
			"no se reanuda, se empieza de cero", destDir, previo.Header.Origen))
	case !p.cfg.Reanudar:
		p.aviso(fmt.Sprintf("hay un escaneo INTERRUMPIDO en %s con %d archivos ya "+
			"recuperados; usa -reanudar para continuar desde el byte %d en lugar de "+
			"empezar de cero", destDir, len(previo.Entradas), previo.UltimoOfset))
	default:
		// Reanudación efectiva.
		w, err := manifest.Append(destDir, previo)
		if err != nil {
			return nil, 0, err
		}
		p.vistos = previo.Hashes()

		p.aviso(fmt.Sprintf("reanudando: %d archivos ya recuperados, se continúa "+
			"desde %.2f GB (%.1f%%)",
			len(previo.Entradas),
			float64(previo.UltimoOfset)/(1<<30),
			float64(previo.UltimoOfset)*100/float64(size)))
		return w, previo.UltimoOfset, nil
	}

	w, err := manifest.Create(destDir, manifest.Header{
		Origen:      origen,
		OrigenBytes: size,
		Destino:     destDir,
		Modo:        p.cfg.Modo,
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
//
// Los mensajes van por callback y no a stdout: así el paquete no impone una
// forma de presentarlos y los tests pueden comprobarlos.
func ComprobarEspacio(destDir string, origenBytes, minFree int64, aviso func(string)) error {
	if aviso == nil {
		aviso = func(string) {}
	}

	libre, err := blockdev.FreeSpace(destDir)
	if err != nil {
		// No poder consultarlo no debe impedir trabajar, pero sí decirlo.
		aviso(fmt.Sprintf("no se pudo comprobar el espacio libre en %s: %v", destDir, err))
		return nil
	}

	if libre < minFree {
		return fmt.Errorf(
			"solo hay %.2f GB libres en %s y se exigen al menos %.2f GB.\n"+
				"   Libera espacio o elige otro destino con -out",
			float64(libre)/(1<<30), destDir, float64(minFree)/(1<<30))
	}

	if libre < origenBytes {
		aviso(fmt.Sprintf(
			"el destino tiene %.2f GB libres y el origen mide %.2f GB; suele bastar, "+
				"porque no todo el disco es contenido recuperable, pero el escaneo se "+
				"detendrá si se agota",
			float64(libre)/(1<<30), float64(origenBytes)/(1<<30)))
	}
	return nil
}

// =========================================================================
// Modo LIST
// =========================================================================
func (p *Pipeline) runList(ctx context.Context) (bool, error) {
	src, size := p.src, p.size
	fmt.Fprintln(p.salida, "📂 Intentando leer la estructura del sistema de archivos...")

	lister := filesystem.NewLister(src, size)
	fsType := lister.FSType()
	if fsType == "unknown" {
		fmt.Fprintln(p.salida, "⚠️  No se reconoció un sistema de archivos válido.")
		return false, nil
	}

	fmt.Fprintf(p.salida, "✅ Sistema de archivos detectado: %s\n", fsType)

	entries, err := lister.List()
	if err != nil || len(entries) == 0 {
		if err != nil {
			fmt.Fprintf(p.salida, "⚠️  %v\n", err)
		} else {
			fmt.Fprintln(p.salida, "⚠️  FS detectado, pero no se pudieron leer entradas válidas.")
		}
		return false, nil
	}
	fmt.Fprintf(p.salida, "📋 %d entradas encontradas. Extrayendo...\n", len(entries))

	extractor := filesystem.NewExtractor(src)
	recuperados := 0

	for _, entry := range entries {
		select {
		case <-ctx.Done():
			fmt.Fprintln(p.salida, "\n⚠️  Cancelado por el usuario.")
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

		stagePath := filepath.Join(p.staging, fmt.Sprintf("%d_%s", entry.Offset, safeName))
		if _, err := extractor.ExtractTo(entry, stagePath); err != nil {
			os.Remove(stagePath)
			continue
		}

		// En modo list conservamos la carpeta original: es información que el
		// carving no puede recuperar y tiene valor por sí misma.
		relDir := output.SanitizeRelPath(filepath.Dir(entry.Path))
		p.process(recoveredFile{
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

	fmt.Fprintf(p.salida, "✅ Extracción por sistema de archivos completada (%d archivos).\n", recuperados)
	return recuperados > 0, nil
}

// =========================================================================
// Modo CARVE
// =========================================================================

func (p *Pipeline) runCarve(ctx context.Context) error {
	src, size := p.src, p.size
	devicePath, sigFile, category, desde := p.cfg.Origen, p.cfg.SigFile, p.cfg.Categoria, p.desde
	fmt.Fprintln(p.salida, "\n🔪 Iniciando file carving (búsqueda por firmas mágicas)...")

	reg, err := buildRegistry(sigFile, category)
	if err != nil {
		return err
	}
	fmt.Fprintf(p.salida, "🔎 %d firmas activas.\n", reg.Count())

	writer, err := output.NewSafeWriter(p.staging, devicePath)
	if err != nil {
		return err
	}

	c := carver.New(src, size, writer, reg)
	if desde > 0 {
		c.SetStartOffset(desde)
	}
	c.SetCancelChannel(ctx.Done())
	c.SetProgressCallback(func(prog scanner.Progress) {
		if p.OnProgreso != nil {
			p.OnProgreso(prog)
		}
		fmt.Fprintf(p.salida, "\r   %.1f%%  %.1f MB/s  ETA %s      ",
			prog.Percent, prog.SpeedMBps, prog.ETA.Round(1e9))
	})

	results, err := c.Run()

	// Recoger las regiones ilegibles para el manifiesto: saber QUE no se pudo
	// leer es tan util como saber que si.
	for _, r := range c.Ilegibles() {
		p.ilegibles = append(p.ilegibles, manifest.RegionJSON{Offset: r.Offset, Length: r.Length})
	}
	fmt.Fprintln(p.salida)
	if err != nil && len(results) == 0 {
		return fmt.Errorf("carving fallido: %w", err)
	}
	if err != nil {
		fmt.Fprintf(p.salida, "⚠️  El escaneo terminó antes de tiempo: %v\n", err)
	}

	fmt.Fprintf(p.salida, "🔍 Carving finalizado. Procesando %d archivos...\n", len(results))

	for _, r := range results {
		// Intentar recuperar el nombre original. Fallar es lo normal.
		name := filepath.Base(r.Path)
		if p.resolver != nil {
			if original, err := p.resolver.Resolve(r.Path, r.Offset, r.Size); err == nil && original != "" {
				if safe := namerecovery.Sanitize(original); safe != "" {
					name = safe
				}
			}
		}
		p.process(recoveredFile{
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
func (p *Pipeline) process(r recoveredFile) {
	entry := manifest.Entry{
		Offset: r.offset, Size: r.size, Metodo: r.metodo,
		Formato: r.formato, SHA256: r.sha256, FooterHallado: r.conFooter,
	}

	// 0. Deduplicar por contenido. El SHA256 ya se calculó al escribir, así que
	// esto no cuesta ninguna lectura extra. Sin ello, un archivo presente diez
	// veces en el disco produce diez copias en la salida.
	if r.sha256 != "" && p.vistos != nil {
		if p.vistos[r.sha256] {
			os.Remove(r.stagePath)
			p.stats.Duplicado++
			entry.Descarte = "duplicado por contenido (SHA256 ya recuperado)"
			p.anotar(entry)
			return
		}
		p.vistos[r.sha256] = true
	}

	// 1. Validar la estructura interna.
	val := validate.Result{Estado: validate.SinComprobar, Score: 0.5, Metodo: "ninguno"}
	if r.formato != "" {
		val = validate.File(r.stagePath, r.formato, p.validOpts)
	}
	entry.Validacion = val.Estado
	entry.ValidMetodo = val.Metodo
	entry.ValidMotivo = val.Motivo

	// 2. Clasificar. Un archivo corrupto no se clasifica: la heurística lee
	// EXIF y dimensiones, y sobre datos contaminados produce respuestas sin
	// sentido que además irían al .meta.json como si fueran ciertas.
	var verdict *classifier.Result
	if p.classifier != nil && val.Estado != validate.Corrupto {
		if res, err := p.classifier.Classify(r.stagePath, r.offset); err == nil {
			verdict = res
			entry.Categoria = res.Category
			entry.EsUsuario = res.IsUserContent
		}
	}

	entry.Integridad = integridad(val, verdict, r.conFooter)

	// 3. Decidir destino.
	categoria, targetBase := p.destino(val, verdict)

	// Con -user-only no llegamos a escribir lo que vamos a descartar.
	if p.cfg.SoloUsuario && categoria != "user" {
		os.Remove(r.stagePath)
		p.stats.Descartado++
		entry.Descarte = "solo se conserva contenido de usuario"
		p.anotar(entry)
		return
	}

	targetDir := targetBase
	if r.relDir != "" {
		targetDir = filepath.Join(targetBase, r.relDir)
	}

	finalPath, err := output.Place(r.stagePath, targetDir, r.nombre)
	if err != nil {
		fmt.Fprintf(p.salida, "\n⚠️  No se pudo colocar %s: %v\n", filepath.Base(r.stagePath), err)
		os.Remove(r.stagePath)
		p.stats.Error++
		entry.Descarte = "error al colocar: " + err.Error()
		p.anotar(entry)
		return
	}
	entry.Destino = finalPath

	// Los metadatos se escriben DESPUÉS de que el archivo esté en su sitio: así
	// el directorio existe con seguridad y el nombre ya es el definitivo.
	if verdict != nil && categoria == "user" {
		p.writeMeta(finalPath, verdict)
	}

	p.incCategoria(categoria)
	p.anotar(entry)

	switch categoria {
	case "user":
		fmt.Fprintf(p.salida, "  ✅ [%s/%s] %s (integridad %.2f)\n",
			categoria, verdict.Category, filepath.Base(finalPath), entry.Integridad)
	case "dudoso":
		fmt.Fprintf(p.salida, "  ⚠️  [dudoso] %s — %s\n", filepath.Base(finalPath), val.Motivo)
	}
}

// destino decide la carpeta según el veredicto de integridad y la clasificación.
//
// Lo corrupto va aparte SIEMPRE, por encima de cualquier otra consideración:
// mezclarlo con lo bueno es exactamente el fallo que esta capa viene a resolver.
func (p *Pipeline) destino(val validate.Result, verdict *classifier.Result) (string, string) {
	if val.Estado == validate.Corrupto {
		return "dudoso", p.dudososDir
	}
	if verdict == nil {
		return "unknown", p.unknownDir
	}
	switch {
	case verdict.IsUserContent:
		return "user", filepath.Join(p.userDir, verdict.Category)
	case verdict.Confidence >= systemConfidence:
		return "system", p.systemDir
	}
	return "unknown", p.unknownDir
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
func (p *Pipeline) anotar(e manifest.Entry) {
	if p.manifest == nil {
		return
	}
	if err := p.manifest.Add(e); err != nil {
		fmt.Fprintf(p.salida, "\n⚠️  No se pudo anotar en el manifiesto: %v\n", err)
	}
}

func (p *Pipeline) writeMeta(finalPath string, verdict *classifier.Result) {
	data, err := json.MarshalIndent(verdict, "", "  ")
	if err != nil {
		return
	}
	if err := os.WriteFile(finalPath+".meta.json", data, 0o644); err != nil {
		fmt.Fprintf(p.salida, "\n⚠️  No se pudieron guardar los metadatos de %s: %v\n",
			filepath.Base(finalPath), err)
	}
}

// incCategoria suma al contador que corresponde. Existe porque las categorias
// son cadenas en el flujo de decision pero campos con nombre en Stats: un mapa
// seria mas corto pero perderia la comprobacion del compilador sobre los
// nombres, que es justo donde se cuelan las erratas silenciosas.
func (p *Pipeline) incCategoria(categoria string) {
	switch categoria {
	case "user":
		p.stats.Usuario++
	case "system":
		p.stats.Sistema++
	case "dudoso":
		p.stats.Dudoso++
	default:
		p.stats.Desconocido++
	}
}

// SetSalida indica dónde escribir el progreso legible. Sin llamarlo, el
// pipeline no imprime nada.
func (p *Pipeline) SetSalida(w io.Writer) {
	if w == nil {
		w = io.Discard
	}
	p.salida = w
}

// MismoDispositivo indica si escribir en destDir escribiría sobre el disco del
// que se está leyendo.
//
// Reutiliza la validación de output creando un SafeWriter de usar y tirar: la
// lógica de comparación (Rdev en Unix, número de disco físico en Windows) vive
// allí porque es quien posee la escritura segura, y duplicarla aquí sería tener
// dos copias de una comprobación de seguridad.
func MismoDispositivo(devicePath, outDir string) (bool, error) {
	if _, err := output.NewSafeWriter(outDir, devicePath); err != nil {
		if strings.Contains(err.Error(), "ERROR DE SEGURIDAD") {
			return true, nil
		}
		return false, err
	}
	return false, nil
}
