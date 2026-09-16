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
//
// Este archivo se queda solo con lo que de verdad le toca a un comando:
// banderas, señales, apertura del dispositivo y presentación. La orquestación
// vive en internal/pipeline, donde se puede probar sin disco ni privilegios.
package main

import (
	"context"
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
	"github.com/edcamero/disk-recover/internal/manifest"
	"github.com/edcamero/disk-recover/internal/pipeline"
)

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
		"desactivar la validación profunda (más rápido, pero no distingue íntegro de corrupto)")
	reanudar := flag.Bool("reanudar", false,
		"continuar un escaneo interrumpido en lugar de empezar de cero")
	minFree := flag.Int64("min-libre", 1<<30,
		"espacio libre mínimo exigido en el destino, en bytes")
	sector := flag.Int64("sector", blockdev.DefaultSectorSize,
		"tamaño de sector para dispositivos en crudo (512 o 4096)")
	flag.Parse()

	if *device == "" {
		return fmt.Errorf("debes especificar -src /dev/sdX o -src imagen.img")
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
	if same, err := pipeline.MismoDispositivo(devicePath, *out); err != nil {
		return err
	} else if same {
		return fmt.Errorf(
			"el destino %q está en el mismo dispositivo que el origen %q; "+
				"nunca escribas en el disco que intentas recuperar", *out, devicePath)
	}

	fmt.Printf("🔍 Analizando: %s (%.2f GB)\n", devicePath, float64(size)/(1<<30))
	fmt.Printf("📁 Salida: %s\n", *out)
	fmt.Printf("⚙️  Modo: %s | Clasificar: %v | Solo usuario: %v\n\n", *mode, *classify, *userOnly)

	if *noValidar {
		fmt.Println("⚠️  Validación profunda DESACTIVADA: no se podrá distinguir")
		fmt.Println("   un archivo íntegro de uno corrupto.")
		fmt.Println()
	}

	// 3. Cancelación ordenada con Ctrl+C. Un carving de 2 TB dura horas.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	p, err := pipeline.New(pipeline.Config{
		Origen:      devicePath,
		Destino:     *out,
		Modo:        *mode,
		Clasificar:  *classify,
		SoloUsuario: *userOnly,
		Validar:     !*noValidar,
		Reanudar:    *reanudar,
		SigFile:     *sigFile,
		Categoria:   *category,
		MinLibre:    *minFree,
	}, reader, size)
	if err != nil {
		return err
	}

	p.SetSalida(os.Stdout)
	p.OnAviso = func(msg string) { fmt.Printf("ℹ️  %s\n", msg) }

	if err := p.Run(ctx); err != nil {
		return err
	}

	fmt.Println("\n" + strings.Repeat("=", 52))
	printStats(p.Stats())
	fmt.Printf("✅ Proceso completado. Revisa: %s\n", *out)
	fmt.Printf("📄 Manifiesto: %s\n", filepath.Join(*out, manifest.Nombre))
	return nil
}

// printStats presenta el recuento. Vive aquí y no en el pipeline porque es
// decisión de presentación: otro llamante querría JSON, o una barra de progreso.
func printStats(s pipeline.Stats) {
	fmt.Println("📊 ESTADÍSTICAS FINALES:")
	fmt.Printf("   📸 Contenido de usuario:      %d\n", s.Usuario)
	fmt.Printf("   ⚙️  Archivos de sistema:       %d\n", s.Sistema)
	fmt.Printf("   ❓ Sin clasificar:            %d\n", s.Desconocido)
	if s.Dudoso > 0 {
		fmt.Printf("   ⚠️  Corruptos (en dudosos/):   %d\n", s.Dudoso)
		fmt.Printf("      Estos archivos NO superaron la validación: su contenido\n")
		fmt.Printf("      no es coherente aunque tengan la forma de su formato.\n")
	}
	if s.Duplicado > 0 {
		fmt.Printf("   ♊ Duplicados omitidos:        %d\n", s.Duplicado)
	}
	if s.Descartado > 0 {
		fmt.Printf("   🗑️  Descartados (-user-only): %d\n", s.Descartado)
	}
	if s.Error > 0 {
		fmt.Printf("   ⚠️  Errores al guardar:       %d\n", s.Error)
	}
}

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
