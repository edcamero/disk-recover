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
	"strings"
	"syscall"

	"github.com/edcamero/disk-recover/internal/blockdev"
	"github.com/edcamero/disk-recover/internal/carver"
	"github.com/edcamero/disk-recover/internal/classifier"
	"github.com/edcamero/disk-recover/internal/filesystem"
	"github.com/edcamero/disk-recover/internal/namerecovery"
	"github.com/edcamero/disk-recover/internal/output"
	"github.com/edcamero/disk-recover/internal/scanner"
	"github.com/edcamero/disk-recover/internal/signatures"
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

	// 1. Abrir el origen en solo lectura. Nunca se escribe en él.
	src, err := os.Open(*device)
	if err != nil {
		return fmt.Errorf("no se pudo abrir %s: %w", *device, err)
	}
	defer src.Close()

	size, err := sourceSize(src)
	if err != nil {
		return err
	}

	// Sobre un dispositivo en crudo, las lecturas tienen que ir alineadas a
	// sector. El carver no lo cumple por sí solo: al extraer un archivo lee
	// exactamente sus bytes, y un JPEG rara vez mide un múltiplo de 512. En
	// Windows esa última lectura desalineada devuelve ERROR_INVALID_PARAMETER,
	// así que sin este envoltorio no se recuperaría ni un archivo.
	var reader io.ReaderAt = src
	if blockdev.IsRawDevice(*device) {
		reader = blockdev.NewAligned(src, *sector, size)
		fmt.Printf("💽 Dispositivo en crudo: lecturas alineadas a %d bytes\n", *sector)
	}

	// 2. Comprobar que no vamos a escribir sobre el propio disco que leemos.
	// Se hace ANTES de crear ningún directorio.
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return fmt.Errorf("no se pudo crear %s: %w", *out, err)
	}
	if same, err := sameDeviceCheck(*device, *out); err != nil {
		return err
	} else if same {
		return fmt.Errorf(
			"el destino %q está en el mismo dispositivo que el origen %q; "+
				"nunca escribas en el disco que intentas recuperar", *out, *device)
	}

	fmt.Printf("🔍 Analizando: %s (%.2f GB)\n", *device, float64(size)/(1<<30))
	fmt.Printf("📁 Salida: %s\n", *out)
	fmt.Printf("⚙️  Modo: %s | Clasificar: %v | Solo usuario: %v\n\n", *mode, *classify, *userOnly)

	// 3. Cancelación ordenada con Ctrl+C. Un carving de 2 TB dura horas.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	app := &app{
		out:        *out,
		userDir:    filepath.Join(*out, "user_content"),
		systemDir:  filepath.Join(*out, "system_files"),
		unknownDir: filepath.Join(*out, "unknown"),
		staging:    filepath.Join(*out, ".staging"),
		userOnly:   *userOnly,
		stats:      map[string]int{},
	}
	if *classify {
		app.classifier = classifier.New()
		app.resolver = namerecovery.NewResolver(reader)
	}

	if err := os.MkdirAll(app.staging, 0o755); err != nil {
		return fmt.Errorf("no se pudo crear el directorio temporal: %w", err)
	}
	defer os.Remove(app.staging) // solo funciona si quedó vacío, que es lo deseable

	// 4. FASE LIST
	listOK := false
	if *mode == "auto" || *mode == "list" {
		listOK, err = app.runList(ctx, reader, size)
		if err != nil {
			return err
		}
	}

	if *mode == "list" {
		app.printStats()
		return nil
	}

	// 5. FASE CARVE: fallback si list no dio nada, o si se pidió explícitamente.
	if !listOK || *mode == "carve" {
		if err := app.runCarve(ctx, reader, size, *device, *sigFile, *category); err != nil {
			return err
		}
	}

	fmt.Println("\n" + strings.Repeat("=", 52))
	app.printStats()
	fmt.Printf("✅ Proceso completado. Revisa: %s\n", *out)
	return nil
}

// app agrupa el estado compartido entre las dos fases.
type app struct {
	out        string
	userDir    string
	systemDir  string
	unknownDir string
	staging    string

	classifier *classifier.Classifier
	resolver   *namerecovery.Resolver
	userOnly   bool
	stats      map[string]int
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
	recovered := 0

	for _, entry := range entries {
		select {
		case <-ctx.Done():
			fmt.Println("\n⚠️  Cancelado por el usuario.")
			return recovered > 0, nil
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
		a.process(stagePath, safeName, relDir, entry.Offset)
		recovered++
	}

	fmt.Printf("✅ Extracción por sistema de archivos completada (%d archivos).\n", recovered)
	return recovered > 0, nil
}

// =========================================================================
// Modo CARVE
// =========================================================================

func (a *app) runCarve(ctx context.Context, src io.ReaderAt, size int64, devicePath, sigFile, category string) error {
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
	c.SetCancelChannel(ctx.Done())
	c.SetProgressCallback(func(p scanner.Progress) {
		fmt.Printf("\r   %.1f%%  %.1f MB/s  ETA %s      ", p.Percent, p.SpeedMBps, p.ETA.Round(1e9))
	})

	results, err := c.Run()
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
		a.process(r.Path, name, "", r.Offset)
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

// process clasifica un archivo ya extraído en staging y lo mueve a su destino.
func (a *app) process(stagePath, desiredName, relDir string, offset int64) {
	category := "unknown"
	targetBase := a.unknownDir
	var verdict *classifier.Result

	if a.classifier != nil {
		res, err := a.classifier.Classify(stagePath, offset)
		if err == nil {
			verdict = res
			switch {
			case res.IsUserContent:
				category = "user"
				targetBase = filepath.Join(a.userDir, res.Category)
			case res.Confidence >= systemConfidence:
				category = "system"
				targetBase = a.systemDir
			}
		}
	}

	// Con -user-only no llegamos a escribir lo que vamos a descartar, en lugar
	// de escribirlo y borrarlo después.
	if a.userOnly && category != "user" {
		os.Remove(stagePath)
		a.stats["descartado"]++
		return
	}

	targetDir := targetBase
	if relDir != "" {
		targetDir = filepath.Join(targetBase, relDir)
	}

	finalPath, err := output.Place(stagePath, targetDir, desiredName)
	if err != nil {
		fmt.Printf("\n⚠️  No se pudo colocar %s: %v\n", filepath.Base(stagePath), err)
		os.Remove(stagePath)
		a.stats["error"]++
		return
	}

	// Los metadatos se escriben DESPUÉS de que el archivo esté en su sitio: así
	// el directorio existe con seguridad y el nombre ya es el definitivo. Antes
	// se escribían apuntando a un directorio que aún no existía, y el error se
	// descartaba, así que los metadatos se perdían en silencio.
	if verdict != nil && category == "user" {
		writeMeta(finalPath, verdict)
	}

	a.stats[category]++

	if category == "user" {
		fmt.Printf("  ✅ [%s/%s] %s (confianza %.2f)\n",
			category, verdict.Category, filepath.Base(finalPath), verdict.Confidence)
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
	if n := a.stats["descartado"]; n > 0 {
		fmt.Printf("   🗑️  Descartados (-user-only): %d\n", n)
	}
	if n := a.stats["error"]; n > 0 {
		fmt.Printf("   ⚠️  Errores al guardar:       %d\n", n)
	}
}

// =========================================================================
// Utilidades
// =========================================================================

// sourceSize determina el tamaño del origen.
//
// Stat().Size() devuelve 0 para dispositivos de bloque en Linux: st_size solo
// tiene sentido en archivos regulares. Por eso hay que buscar el final del
// dispositivo. Sin esto, -src /dev/sdb1 aborta con "el tamaño del origen es 0",
// que era justo el caso de uso principal de la herramienta.
func sourceSize(f *os.File) (int64, error) {
	if info, err := f.Stat(); err == nil && info.Size() > 0 {
		return info.Size(), nil
	}

	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return 0, fmt.Errorf("no se pudo determinar el tamaño de %s: %w", f.Name(), err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return 0, fmt.Errorf("no se pudo rebobinar %s: %w", f.Name(), err)
	}
	if size <= 0 {
		return 0, fmt.Errorf("%s no tiene tamaño legible", f.Name())
	}
	return size, nil
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
