package output

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	// copyBufferSize: el default de io.Copy son 32 KB. Con archivos de varios
	// GB, subirlo a 1 MB reduce las llamadas al sistema en un factor de 32.
	copyBufferSize = 1 << 20

	// maxCollisionRetries acota la búsqueda de nombre libre. Si se agota, algo
	// va mal de verdad y es mejor fallar que girar indefinidamente.
	maxCollisionRetries = 10000
)

// WriteResult contiene el resultado de una operación de escritura
type WriteResult struct {
	FinalPath string
	Size      int64
	SHA256    string
	IsRenamed bool // True si se tuvo que cambiar el nombre por colisión
}

// SafeWriter maneja la escritura segura de archivos recuperados
type SafeWriter struct {
	destDir      string
	sourcePath   string // Origen, para no escribir nunca sobre el disco que leemos
	filesWritten int64
	bytesWritten int64
}

// NewSafeWriter crea un nuevo escritor seguro
func NewSafeWriter(destDir string, sourcePath string) (*SafeWriter, error) {
	// 1. Crear directorio de destino si no existe
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return nil, fmt.Errorf("no se pudo crear el directorio de destino: %w", err)
	}

	// 2. Comprobar que el origen existe antes de seguir
	if _, err := os.Stat(sourcePath); err != nil {
		return nil, fmt.Errorf("no se pudo acceder al origen: %w", err)
	}

	// 3. VALIDACIÓN CRÍTICA: escribir en el disco que estamos recuperando destruye
	// justo los datos que buscamos. Es un error fatal, no un aviso.
	same, err := sameUnderlyingDevice(sourcePath, destDir)
	if err != nil {
		return nil, fmt.Errorf("no se pudo comparar origen y destino: %w", err)
	}
	if same {
		return nil, fmt.Errorf(
			"ERROR DE SEGURIDAD: el destino %q está en el mismo dispositivo que el origen %q; "+
				"nunca escribas en el disco que intentas recuperar", destDir, sourcePath)
	}

	return &SafeWriter{
		destDir:    destDir,
		sourcePath: sourcePath,
	}, nil
}

// Save escribe un stream de datos de forma segura y atómica
func (w *SafeWriter) Save(r io.Reader, desiredName string) (*WriteResult, error) {
	// 1. Sanitizar el nombre del archivo
	safeName := SanitizeFilename(desiredName)
	if safeName == "" {
		safeName = "recuperado_sin_nombre"
	}

	// 2. Reservar un nombre libre. O_EXCL hace la reserva atómica: si dos
	// escrituras compiten por el mismo nombre, una de las dos falla con EEXIST
	// y prueba el siguiente sufijo. La versión anterior hacía Stat y luego
	// creaba, con una ventana entre ambas en la que otro proceso podía ganar.
	finalPath, isRenamed, err := reserveName(w.destDir, safeName)
	if err != nil {
		return nil, err
	}

	// 3. Escritura atómica: primero a un temporal en el MISMO directorio, para
	// que el Rename final sea una operación dentro del mismo sistema de
	// archivos y por tanto atómica.
	tmpPath := finalPath + ".tmp"
	outFile, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		os.Remove(finalPath)
		return nil, fmt.Errorf("no se pudo crear archivo temporal: %w", err)
	}

	// 4. Copiar datos y calcular el hash en la misma pasada.
	hasher := sha256.New()
	size, err := io.CopyBuffer(io.MultiWriter(outFile, hasher), r, make([]byte, copyBufferSize))
	if err != nil {
		outFile.Close()
		os.Remove(tmpPath)
		os.Remove(finalPath)
		return nil, fmt.Errorf("error escribiendo datos: %w", err)
	}

	// 5. Forzar los datos a disco ANTES del rename. Sin esto, "escritura
	// atómica" solo protege frente a un fallo del proceso, no frente a un corte
	// de energía: el rename puede llegar al disco antes que el contenido y
	// dejar un archivo con el nombre correcto y cero bytes dentro. Esta
	// herramienta corre durante horas sobre hardware que ya está fallando.
	if err := outFile.Sync(); err != nil {
		outFile.Close()
		os.Remove(tmpPath)
		os.Remove(finalPath)
		return nil, fmt.Errorf("error sincronizando a disco: %w", err)
	}
	if err := outFile.Close(); err != nil {
		os.Remove(tmpPath)
		os.Remove(finalPath)
		return nil, fmt.Errorf("error cerrando archivo: %w", err)
	}

	// 6. Rename sobre el marcador que reservamos en el paso 2.
	if err := os.Rename(tmpPath, finalPath); err != nil {
		if err := copyFileFallback(tmpPath, finalPath); err != nil {
			os.Remove(tmpPath)
			os.Remove(finalPath)
			return nil, fmt.Errorf("error en renombrado atómico: %w", err)
		}
		os.Remove(tmpPath)
	}

	// 7. Actualizar estadísticas
	w.filesWritten++
	w.bytesWritten += size

	return &WriteResult{
		FinalPath: finalPath,
		Size:      size,
		SHA256:    fmt.Sprintf("%x", hasher.Sum(nil)),
		IsRenamed: isRenamed,
	}, nil
}

// Stats devuelve las estadísticas de escritura
func (w *SafeWriter) Stats() (files int64, bytes int64) {
	return w.filesWritten, w.bytesWritten
}

// Place mueve un archivo que ya existe al directorio destino, resolviendo
// colisiones igual que Save. Se usa para reubicar un archivo ya extraído (por
// ejemplo, tras clasificarlo) sin volver a copiar sus bytes: dentro del mismo
// sistema de archivos, un rename es una operación de metadatos, así que da igual
// que el archivo pese 5 GB.
func Place(srcPath, destDir, desiredName string) (string, error) {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return "", fmt.Errorf("no se pudo crear %s: %w", destDir, err)
	}

	safeName := SanitizeFilename(desiredName)
	if safeName == "" {
		safeName = filepath.Base(srcPath)
	}

	finalPath, _, err := reserveName(destDir, safeName)
	if err != nil {
		return "", err
	}

	if err := os.Rename(srcPath, finalPath); err != nil {
		// Sistemas de archivos distintos: copiar en streaming y borrar el
		// origen. Nunca leer el archivo entero en memoria.
		if cerr := copyFileFallback(srcPath, finalPath); cerr != nil {
			os.Remove(finalPath)
			return "", fmt.Errorf("no se pudo mover %s: %w", srcPath, cerr)
		}
		os.Remove(srcPath)
	}

	return finalPath, nil
}

// =========================================================================
// Funciones Auxiliares
// =========================================================================

// reserveName encuentra un nombre libre en destDir y lo reserva creando el
// archivo vacío con O_EXCL. Devuelve la ruta reservada y si hubo que renombrar
// por colisión.
//
// Reservar de verdad (en lugar de comprobar con Stat) es lo que impide que dos
// archivos recuperados distintos acaben pisándose. La versión anterior usaba
// offset%0xFFFF como sufijo "único": 65.535 valores posibles para un disco con
// decenas de miles de archivos, con os.Rename sobrescribiendo en silencio al
// colisionar.
func reserveName(destDir, safeName string) (string, bool, error) {
	ext := filepath.Ext(safeName)
	stem := strings.TrimSuffix(safeName, ext)

	for counter := 0; counter < maxCollisionRetries; counter++ {
		candidate := filepath.Join(destDir, safeName)
		if counter > 0 {
			candidate = filepath.Join(destDir, fmt.Sprintf("%s_%d%s", stem, counter, ext))
		}

		f, err := os.OpenFile(candidate, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err == nil {
			f.Close()
			return candidate, counter > 0, nil
		}
		if !os.IsExist(err) {
			return "", false, fmt.Errorf("no se pudo reservar %s: %w", candidate, err)
		}
	}

	return "", false, fmt.Errorf("demasiadas colisiones de nombre para %q", safeName)
}

// windowsReserved son nombres de dispositivo de MS-DOS que Windows sigue
// interceptando. Escribir en "NUL" descarta los datos en silencio, que en una
// herramienta de recuperación es el peor final posible.
var windowsReserved = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true,
	"COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true,
	"LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
}

// maxNameBytes acota la longitud. La mayoría de sistemas de archivos corta en
// 255 bytes por componente; dejamos margen para los sufijos anticolisión.
const maxNameBytes = 200

// SanitizeFilename convierte un nombre no confiable en un nombre de archivo
// seguro, o en cadena vacía si no queda nada utilizable.
//
// Esto es una frontera de seguridad, no una comodidad: el nombre procede de los
// bytes de un disco ajeno y la herramienta suele ejecutarse como root. Un
// nombre como "../../../etc/cron.d/x" tiene que salir de aquí inutilizado.
func SanitizeFilename(name string) string {
	if name == "" {
		return ""
	}

	// 1. Normalizar separadores y quedarnos con el último componente. Hacerlo
	// primero elimina cualquier intento de recorrido de rutas. No basta con
	// filepath.Base: en Linux no trata '\' como separador, así que un nombre
	// creado en Windows pasaría entero.
	name = strings.ReplaceAll(name, "\\", "/")
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}

	// 2. "." y ".." no dejan nada seguro detrás.
	if strings.Trim(name, ".") == "" {
		return ""
	}

	// 3. Descartar caracteres de control y sustituir los inválidos.
	var sb strings.Builder
	for _, r := range name {
		switch {
		case r < 0x20 || r == 0x7F:
			// Caracteres de control: fuera.
		case strings.ContainsRune(`<>:"/\|?*`, r):
			sb.WriteRune('_')
		default:
			sb.WriteRune(r)
		}
	}
	name = strings.Trim(sb.String(), " .")
	if name == "" {
		return ""
	}

	// 4. Desactivar nombres reservados con un prefijo.
	base := name
	if i := strings.Index(base, "."); i > 0 {
		base = base[:i]
	}
	if windowsReserved[strings.ToUpper(base)] {
		name = "_" + name
	}

	// 5. Acotar longitud sin partir un carácter multibyte ni perder la
	// extensión. La versión anterior hacía name[:200-len(ext)], que entra en
	// pánico si la extensión mide más de 200 bytes.
	if len(name) > maxNameBytes {
		ext := filepath.Ext(name)
		if len(ext) > maxNameBytes/2 {
			ext = "" // extensión absurda: casi seguro basura del disco
		}
		stem := name[:len(name)-len(filepath.Ext(name))]
		name = truncateRunes(stem, maxNameBytes-len(ext)) + ext
	}

	return strings.Trim(name, " .")
}

// SanitizeRelPath sanea una ruta relativa procedente del disco auditado,
// componente a componente, y devuelve algo que siempre queda por debajo del
// directorio base.
//
// filepath.Join limpia los ".." pero NO confina: Join("out", "../../etc") da
// "../etc", fuera del destino. Por eso aquí los componentes "." y ".." se
// descartan en lugar de interpretarse.
func SanitizeRelPath(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")

	var parts []string
	for _, comp := range strings.Split(p, "/") {
		switch comp {
		case "", ".", "..":
			continue // nunca se interpretan: se tiran
		}
		if safe := SanitizeFilename(comp); safe != "" {
			parts = append(parts, safe)
		}
	}

	if len(parts) == 0 {
		return ""
	}
	return filepath.Join(parts...)
}

// truncateRunes recorta s a como mucho max bytes sin partir un rune, que
// produciría UTF-8 inválido en el nombre del archivo.
func truncateRunes(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && s[cut]&0xC0 == 0x80 {
		cut--
	}
	return s[:cut]
}

// copyFileFallback se usa si os.Rename falla entre distintos puntos de montaje
func copyFileFallback(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
