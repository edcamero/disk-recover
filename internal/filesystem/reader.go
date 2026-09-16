package filesystem

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	readChunk = 64 << 10

	// maxConsecutiveFailures acota cuántos bloques ilegibles seguidos toleramos
	// antes de dar el archivo por perdido. Sin este tope, una entrada con offset
	// corrupto (algo habitual en una FAT dañada) hace que fallen todas las
	// lecturas y se escriba entry.Size bytes de ceros: un Size corrupto de 4 GB
	// llena el disco de destino sin recuperar nada.
	maxConsecutiveFailures = 64
)

// Extractor copia archivos del FS dañado al destino tolerando sectores malos.
type Extractor struct {
	src io.ReaderAt
}

// NewExtractor crea un Extractor sobre el origen dado.
func NewExtractor(src io.ReaderAt) *Extractor {
	return &Extractor{src: src}
}

// ExtractResult describe cómo fue la extracción de un archivo.
type ExtractResult struct {
	Written    int64 // bytes escritos en total
	ZeroFilled int64 // de esos, cuántos son relleno por sectores ilegibles
}

// Complete indica si el archivo se leyó entero sin relleno.
func (r ExtractResult) Complete() bool { return r.ZeroFilled == 0 }

// ExtractTo copia los datos de entry al path indicado.
//
// destPath lo construye y sanea el llamante a propósito: entry.Name y
// entry.Path vienen de bytes del disco auditado y no son de fiar, así que la
// decisión de dónde escribir no puede tomarse aquí a partir de ellos.
func (e *Extractor) ExtractTo(entry FileEntry, destPath string) (ExtractResult, error) {
	var res ExtractResult

	if entry.IsDir || entry.Size <= 0 {
		return res, fmt.Errorf("entrada no extraíble: %q", entry.Name)
	}

	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return res, err
	}

	f, err := os.Create(destPath)
	if err != nil {
		return res, err
	}
	defer f.Close()

	// NTFS residente: el contenido ya está en memoria, no hay que leer del disco.
	if entry.Data != nil {
		n, werr := f.Write(entry.Data)
		res.Written = int64(n)
		if !entry.ModTime.IsZero() {
			os.Chtimes(destPath, entry.ModTime, entry.ModTime)
		}
		return res, werr
	}

	// exFAT fragmentado: el archivo ocupa varios extents no contiguos.
	if len(entry.Extents) > 0 {
		buf := make([]byte, readChunk)
		zeroes := make([]byte, readChunk)
		remaining := entry.Size
		for _, ext := range entry.Extents {
			extOff, extLeft := ext.Offset, ext.Size
			for extLeft > 0 && remaining > 0 {
				toRead := int64(len(buf))
				if toRead > extLeft {
					toRead = extLeft
				}
				if toRead > remaining {
					toRead = remaining
				}
				n, rerr := e.src.ReadAt(buf[:toRead], extOff)
				if n > 0 {
					if _, werr := f.Write(buf[:n]); werr != nil {
						return res, fmt.Errorf("error escribiendo %s: %w", destPath, werr)
					}
					res.Written += int64(n)
				}
				if rerr != nil {
					if gap := toRead - int64(n); gap > 0 {
						if _, werr := f.Write(zeroes[:gap]); werr != nil {
							return res, fmt.Errorf("error escribiendo relleno en %s: %w", destPath, werr)
						}
						res.Written += gap
						res.ZeroFilled += gap
					}
				}
				extOff += toRead
				extLeft -= toRead
				remaining -= toRead
			}
			if remaining <= 0 {
				break
			}
		}
		if !entry.ModTime.IsZero() {
			os.Chtimes(destPath, entry.ModTime, entry.ModTime)
		}
		return res, nil
	}

	buf := make([]byte, readChunk)
	zeroes := make([]byte, readChunk) // reutilizado; antes se asignaba por iteración

	remaining := entry.Size
	offset := entry.Offset
	consecutiveFailures := 0

	for remaining > 0 {
		toRead := int64(len(buf))
		if toRead > remaining {
			toRead = remaining
		}

		n, rerr := e.src.ReadAt(buf[:toRead], offset)
		if n > 0 {
			if _, werr := f.Write(buf[:n]); werr != nil {
				return res, fmt.Errorf("error escribiendo %s: %w", destPath, werr)
			}
			res.Written += int64(n)
			consecutiveFailures = 0
		}

		if rerr != nil {
			// Rellenar con ceros el hueco ilegible mantiene alineados los
			// offsets del resto del archivo, que es lo que permite que un JPEG
			// con un sector malo en medio siga siendo visible.
			if gap := toRead - int64(n); gap > 0 {
				if _, werr := f.Write(zeroes[:gap]); werr != nil {
					return res, fmt.Errorf("error escribiendo relleno en %s: %w", destPath, werr)
				}
				res.Written += gap
				res.ZeroFilled += gap
			}

			consecutiveFailures++
			if consecutiveFailures >= maxConsecutiveFailures {
				return res, fmt.Errorf(
					"%d bloques ilegibles seguidos en offset %d: se abandona %s",
					consecutiveFailures, offset, destPath)
			}
		}

		// Avanzar por toRead y no por n: el hueco ya se rellenó, así que el
		// resto del archivo conserva su posición relativa.
		offset += toRead
		remaining -= toRead
	}

	// Un archivo que es todo relleno no contiene nada recuperable.
	if res.Written > 0 && res.ZeroFilled == res.Written {
		return res, fmt.Errorf("%s es completamente ilegible", destPath)
	}

	if !entry.ModTime.IsZero() {
		os.Chtimes(destPath, entry.ModTime, entry.ModTime)
	}

	return res, nil
}
