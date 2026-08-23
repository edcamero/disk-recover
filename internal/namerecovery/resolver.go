// Package namerecovery intenta averiguar el nombre original de un archivo
// recuperado por carving, donde la entrada de directorio que lo nombraba ya no
// existe.
//
// Ninguna de las fuentes garantiza acierto: son heurísticas ordenadas de más a
// menos fiable. Devolver cadena vacía es un resultado válido y frecuente.
package namerecovery

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/edcamero/disk-recover/internal/output"
)

// headerBytes es cuánto leemos del archivo extraído para buscar metadatos.
// EXIF y el paquete XMP viven al principio.
const headerBytes = 256 << 10

// Resolver orquesta las distintas fuentes de nombres.
type Resolver struct {
	// src es el origen (disco o imagen), necesario para mirar los bytes que
	// rodean al archivo en busca de restos de la entrada de directorio.
	src io.ReaderAt
}

// NewResolver crea un Resolver sobre el origen del que se está recuperando.
func NewResolver(src io.ReaderAt) *Resolver {
	return &Resolver{src: src}
}

// Resolve intenta recuperar el nombre original del archivo extraído en path,
// que ocupaba size bytes a partir de offset en el origen.
//
// Orden de preferencia:
//  1. Metadatos incrustados (EXIF, XMP): si el archivo dice cómo se llama, es
//     la fuente más fiable porque viaja dentro del propio archivo.
//  2. Restos de la entrada de directorio en los bytes previos al archivo.
//
// Devuelve cadena vacía (sin error) si ninguna fuente da nada utilizable.
func (r *Resolver) Resolve(path string, offset, size int64) (string, error) {
	header, err := readHeader(path)
	if err != nil {
		return "", err
	}

	ext := strings.ToLower(filepath.Ext(path))

	// 1. Metadatos incrustados.
	if name := nameFromMetadata(header); name != "" {
		return ensureExt(name, ext), nil
	}

	// 2. Restos de la entrada de directorio alrededor del archivo.
	if r.src != nil {
		if name := r.scanNearby(offset); name != "" {
			return ensureExt(name, ext), nil
		}
	}

	return "", nil
}

// readHeader lee el principio del archivo extraído, tolerando truncamiento.
func readHeader(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	buf := make([]byte, headerBytes)
	n, err := f.ReadAt(buf, 0)
	if n == 0 && err != nil && err != io.EOF {
		return nil, err
	}
	return buf[:n], nil
}

// ensureExt añade la extensión detectada por firma si el nombre recuperado no
// trae ninguna, o trae una distinta. La firma mágica es más de fiar que el
// nombre: el nombre puede venir de un campo de metadatos arbitrario.
func ensureExt(name, ext string) string {
	if ext == "" {
		return name
	}
	if strings.EqualFold(filepath.Ext(name), ext) {
		return name
	}
	return name + ext
}

// =========================================================================
// Sanitización
// =========================================================================

// Sanitize convierte un nombre no confiable en un nombre de archivo seguro, o
// en cadena vacía si no queda nada utilizable.
//
// Es una frontera de seguridad: el nombre procede de los bytes de un disco ajeno
// y la herramienta suele ejecutarse como root, así que "../../../etc/cron.d/x"
// tiene que salir de aquí inutilizado.
//
// La implementación vive en internal/output porque es ese paquete el que posee
// la escritura segura en disco, y tener dos copias de una comprobación de
// seguridad es la mejor forma de que una de las dos se quede sin arreglar.
func Sanitize(name string) string {
	return output.SanitizeFilename(name)
}
