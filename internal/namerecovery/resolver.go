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

// Cuánto se lee del archivo extraído para buscar metadatos.
//
// Las lecturas están ACOTADAS a propósito, no por elegancia: un vídeo de 2 GB o
// un RAW de 50 MB cargados enteros, multiplicados por miles de archivos
// recuperados, revientan la memoria o dejan el sistema haciendo swap. El
// consumo tiene que depender de estas constantes y no del tamaño del archivo.
const (
	// headerBytes cubre el principio, donde viven EXIF y la mayoría de paquetes
	// XMP. 256 KB deja margen sobre el APP1 de EXIF, que no pasa de 64 KB.
	headerBytes = 256 << 10

	// trailerBytes cubre el FINAL, que es donde varios formatos ponen sus
	// metadatos:
	//
	//	MP4/MOV  el átomo 'moov' va al final cuando se graba en streaming,
	//	         que es lo que hacen las cámaras y los móviles
	//	XMP      Adobe lo escribe al final en algunos flujos de exportación
	//	ID3v1    los últimos 128 bytes de un MP3
	//
	// Sin esto, el nombre de un vídeo de cámara no se recupera nunca aunque
	// esté escrito dentro del archivo.
	trailerBytes = 256 << 10
)

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
	cabecera, cola, err := leerExtremos(path)
	if err != nil {
		return "", err
	}

	ext := strings.ToLower(filepath.Ext(path))

	// 1. Metadatos al principio: EXIF y la mayoría de paquetes XMP.
	if name := nameFromMetadata(cabecera); name != "" {
		return ensureExt(name, ext), nil
	}

	// 2. Metadatos al FINAL: el átomo 'moov' de un MP4 grabado en streaming, o
	// un XMP escrito al cierre. Se mira aparte porque leer el archivo entero
	// para encontrarlos costaría gigabytes por cada vídeo recuperado.
	if len(cola) > 0 {
		if name := nameFromMetadata(cola); name != "" {
			return ensureExt(name, ext), nil
		}
	}

	// 3. Restos de la entrada de directorio alrededor del archivo.
	if r.src != nil {
		if name := r.scanNearby(offset); name != "" {
			return ensureExt(name, ext), nil
		}
	}

	return "", nil
}

// leerExtremos lee el principio y el final del archivo, nunca su totalidad.
//
// Devuelve la cola vacía cuando el archivo ya cabe entero en la cabecera:
// releerlo duplicaría el trabajo y podría procesar dos veces el mismo metadato.
func leerExtremos(path string) (cabecera, cola []byte, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	size := info.Size()

	buf := make([]byte, headerBytes)
	n, err := f.ReadAt(buf, 0)
	if n == 0 && err != nil && err != io.EOF {
		return nil, nil, err
	}
	cabecera = buf[:n]

	if size <= int64(headerBytes) {
		return cabecera, nil, nil // el archivo entero ya está en la cabecera
	}

	desde := size - int64(trailerBytes)
	if desde < int64(headerBytes) {
		// Solapa con la cabecera: se empieza donde esta acabó, para no releer
		// los mismos bytes.
		desde = int64(headerBytes)
	}

	colaBuf := make([]byte, size-desde)
	m, err := f.ReadAt(colaBuf, desde)
	if m == 0 && err != nil && err != io.EOF {
		// No poder leer el final no invalida lo que ya se leyó del principio.
		return cabecera, nil, nil
	}
	return cabecera, colaBuf[:m], nil
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
