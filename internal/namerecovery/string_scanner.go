package namerecovery

import (
	"strings"
	"unicode/utf16"
)

// Fuente 2: restos de la entrada de directorio en el disco.
//
// Cuando se borra un archivo, sus datos siguen ahí y muy a menudo la entrada de
// directorio que lo nombraba también, en algún cluster cercano. FAT32 guarda los
// nombres largos en UTF-16LE y NTFS igual, así que hay que barrer en ambas
// codificaciones.
//
// Esto es una heurística de último recurso: un acierto es un regalo, un fallo es
// lo normal. Por eso solo aceptamos cadenas que terminen en una extensión
// conocida, lo que reduce muchísimo los falsos positivos.

// scanWindow es cuánto miramos antes del inicio del archivo. Las entradas de
// directorio suelen estar en el mismo cluster o en uno adyacente.
const scanWindow = 64 << 10

// knownExtensions son las extensiones que aceptamos como final de un nombre.
var knownExtensions = []string{
	".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".heic", ".tif", ".tiff",
	".mp4", ".mov", ".avi", ".mkv", ".3gp", ".m4v", ".wmv",
	".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf",
	".zip", ".rar", ".7z", ".mp3", ".wav", ".flac", ".m4a",
	".cr2", ".nef", ".arw", ".dng", ".raf",
}

// scanNearby busca nombres de archivo en la ventana anterior al offset dado.
func (r *Resolver) scanNearby(offset int64) string {
	if r.src == nil || offset <= 0 {
		return ""
	}

	start := offset - scanWindow
	if start < 0 {
		start = 0
	}
	length := offset - start
	if length <= 0 {
		return ""
	}

	buf := make([]byte, length)
	n, _ := r.src.ReadAt(buf, start)
	if n <= 0 {
		return ""
	}
	buf = buf[:n]

	// UTF-16LE primero: es como guardan los nombres largos tanto FAT32 (LFN)
	// como NTFS ($FILE_NAME), así que tiene más probabilidad de acertar.
	if name := lastFilenameUTF16(buf); name != "" {
		return name
	}
	return lastFilenameASCII(buf)
}

// lastFilenameASCII devuelve la última cadena imprimible de la ventana que
// termina en una extensión conocida. "La última" porque la entrada de
// directorio más cercana al archivo es la que con más probabilidad le
// corresponde.
func lastFilenameASCII(buf []byte) string {
	var best string
	var run []byte

	flush := func() {
		if len(run) >= 5 {
			if name := acceptFilename(string(run)); name != "" {
				best = name
			}
		}
		run = run[:0]
	}

	for _, c := range buf {
		if isNameByte(c) {
			run = append(run, c)
			if len(run) > 255 {
				run = run[:0] // cadena absurdamente larga: no es un nombre
			}
			continue
		}
		flush()
	}
	flush()

	return best
}

// lastFilenameUTF16 hace lo mismo sobre texto UTF-16LE.
func lastFilenameUTF16(buf []byte) string {
	var best string
	var run []uint16

	flush := func() {
		if len(run) >= 5 {
			if name := acceptFilename(string(utf16.Decode(run))); name != "" {
				best = name
			}
		}
		run = run[:0]
	}

	for i := 0; i+1 < len(buf); i += 2 {
		lo, hi := buf[i], buf[i+1]
		// Caracteres del plano latino: byte alto 0 y byte bajo imprimible.
		if hi == 0 && isNameByte(lo) {
			run = append(run, uint16(lo))
			if len(run) > 255 {
				run = run[:0]
			}
			continue
		}
		flush()
	}
	flush()

	return best
}

// isNameByte acepta lo que puede aparecer en un nombre de archivo real. No
// incluye separadores de ruta a propósito: si aparecen, la cadena se corta ahí,
// lo que aporta una defensa más contra el recorrido de rutas.
func isNameByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z':
		return true
	case c >= 'A' && c <= 'Z':
		return true
	case c >= '0' && c <= '9':
		return true
	}
	return strings.IndexByte("._- ()[]#&+,'~@", c) >= 0
}

// acceptFilename valida que la cadena parezca un nombre real y la sanea.
func acceptFilename(s string) string {
	s = strings.TrimSpace(s)
	if !looksLikeFilename(s) {
		return ""
	}
	return Sanitize(s)
}

// looksLikeFilename exige extensión conocida, longitud razonable y algo antes
// del punto. Es estricto a propósito: un falso positivo pone un nombre
// equivocado a la foto de alguien.
func looksLikeFilename(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) < 5 || len(s) > 255 {
		return false
	}
	if strings.ContainsAny(s, "/\\") {
		return false
	}

	lower := strings.ToLower(s)
	for _, ext := range knownExtensions {
		if !strings.HasSuffix(lower, ext) {
			continue
		}
		stem := s[:len(s)-len(ext)]
		stem = strings.TrimSpace(stem)
		if stem == "" || strings.Trim(stem, ".") == "" {
			return false
		}
		// Al menos un carácter alfanumérico en el nombre.
		for _, r := range stem {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
				return true
			}
		}
		return false
	}
	return false
}
