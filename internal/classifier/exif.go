package classifier

import (
	"encoding/binary"
	"strings"
	"time"
	"unicode/utf16"
)

// Todo lo que se parsea aquí viene de un disco dañado: bytes truncados,
// desplazamientos que apuntan a cualquier parte y contadores absurdos son la
// norma, no la excepción. Por eso cada lectura está acotada y no hay ni un solo
// acceso a slice sin comprobar. Un panic aquí abortaría la recuperación entera.

const (
	maxIFDEntries = 512 // un IFD real rara vez pasa de 50
	maxIFDDepth   = 4   // IFD0 -> ExifIFD -> Interop; 4 es holgado
)

// Tags TIFF/EXIF que nos interesan.
const (
	tagImageDescription = 0x010E
	tagMake             = 0x010F
	tagModel            = 0x0110
	tagSoftware         = 0x0131
	tagDateTime         = 0x0132
	tagExifIFD          = 0x8769
	tagGPSIFD           = 0x8825
	tagDateTimeOriginal = 0x9003
	tagPixelXDimension  = 0xA002
	tagPixelYDimension  = 0xA003
	tagXPTitle          = 0x9C9B
)

// exifData reúne lo que necesita el clasificador. Todos los campos son
// opcionales por diseño.
type exifData struct {
	HasEXIF     bool
	Make        string
	Model       string
	Software    string
	Description string
	Title       string
	DateTaken   time.Time
	HasGPS      bool
	Width       int
	Height      int
}

// hasCameraInfo indica si el archivo lleva la huella de una cámara real.
func (e *exifData) hasCameraInfo() bool {
	return e.Make != "" || e.Model != ""
}

// tiff da acceso acotado a un bloque TIFF con su endianness.
type tiff struct {
	data []byte
	bo   binary.ByteOrder
}

func (t *tiff) u16(off int) (uint16, bool) {
	if off < 0 || off+2 > len(t.data) {
		return 0, false
	}
	return t.bo.Uint16(t.data[off : off+2]), true
}

func (t *tiff) u32(off int) (uint32, bool) {
	if off < 0 || off+4 > len(t.data) {
		return 0, false
	}
	return t.bo.Uint32(t.data[off : off+4]), true
}

// typeSize devuelve el tamaño en bytes de un tipo TIFF, o 0 si no lo conocemos.
func typeSize(typ uint16) int {
	switch typ {
	case 1, 2, 6, 7: // BYTE, ASCII, SBYTE, UNDEFINED
		return 1
	case 3, 8: // SHORT, SSHORT
		return 2
	case 4, 9, 11: // LONG, SLONG, FLOAT
		return 4
	case 5, 10, 12: // RATIONAL, SRATIONAL, DOUBLE
		return 8
	default:
		return 0
	}
}

// parseEXIF localiza el bloque TIFF dentro de un APP1 de JPEG y lo recorre.
func parseEXIF(data []byte, out *exifData) {
	tiffData, ok := findEXIFSegment(data)
	if !ok {
		return
	}

	if len(tiffData) < 8 {
		return
	}

	var bo binary.ByteOrder
	switch {
	case tiffData[0] == 'I' && tiffData[1] == 'I':
		bo = binary.LittleEndian
	case tiffData[0] == 'M' && tiffData[1] == 'M':
		bo = binary.BigEndian
	default:
		return
	}

	t := &tiff{data: tiffData, bo: bo}

	if magic, ok := t.u16(2); !ok || magic != 42 {
		return
	}
	ifd0, ok := t.u32(4)
	if !ok {
		return
	}

	out.HasEXIF = true
	visited := make(map[int]bool)
	walkIFD(t, int(ifd0), 0, visited, out)
}

// findEXIFSegment recorre los marcadores JPEG buscando el APP1 con firma "Exif".
// Devuelve el bloque TIFF (justo después de "Exif\0\0").
func findEXIFSegment(data []byte) ([]byte, bool) {
	if len(data) < 4 || data[0] != 0xFF || data[1] != 0xD8 {
		return nil, false
	}

	for pos := 2; pos+4 <= len(data); {
		if data[pos] != 0xFF {
			// Relleno o datos corruptos: avanzar hasta el siguiente 0xFF.
			pos++
			continue
		}

		marker := data[pos+1]

		// Marcadores sin payload.
		if marker == 0xD8 || marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7) {
			pos += 2
			continue
		}
		// Inicio del scan: a partir de aquí ya no hay cabeceras que leer.
		if marker == 0xDA || marker == 0xD9 {
			return nil, false
		}

		segLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		if segLen < 2 || pos+2+segLen > len(data) {
			return nil, false
		}

		if marker == 0xE1 {
			payload := data[pos+4 : pos+2+segLen]
			if len(payload) > 6 && string(payload[:4]) == "Exif" {
				return payload[6:], true
			}
		}

		pos += 2 + segLen
	}

	return nil, false
}

// walkIFD recorre un IFD y sus punteros anidados. visited corta los ciclos que
// produce una tabla corrupta; depth acota la recursión legítima.
func walkIFD(t *tiff, offset, depth int, visited map[int]bool, out *exifData) {
	if depth > maxIFDDepth || offset <= 0 || visited[offset] {
		return
	}
	visited[offset] = true

	count, ok := t.u16(offset)
	if !ok {
		return
	}
	if int(count) > maxIFDEntries {
		count = maxIFDEntries
	}

	for i := 0; i < int(count); i++ {
		entry := offset + 2 + i*12
		if entry+12 > len(t.data) {
			return
		}

		tag, ok1 := t.u16(entry)
		typ, ok2 := t.u16(entry + 2)
		n, ok3 := t.u32(entry + 4)
		if !ok1 || !ok2 || !ok3 {
			return
		}

		switch tag {
		case tagExifIFD, tagGPSIFD:
			sub, ok := t.u32(entry + 8)
			if !ok {
				continue
			}
			if tag == tagGPSIFD {
				// La sola presencia de un GPS IFD con contenido ya es señal.
				if c, ok := t.u16(int(sub)); ok && c > 0 && c <= maxIFDEntries {
					out.HasGPS = true
				}
			}
			walkIFD(t, int(sub), depth+1, visited, out)
			continue
		}

		val, ok := entryValue(t, entry, typ, n)
		if !ok {
			continue
		}

		switch tag {
		case tagMake:
			out.Make = cleanASCII(val)
		case tagModel:
			out.Model = cleanASCII(val)
		case tagSoftware:
			out.Software = cleanASCII(val)
		case tagImageDescription:
			out.Description = cleanASCII(val)
		case tagXPTitle:
			out.Title = decodeUCS2(val)
		case tagDateTimeOriginal:
			if ts, ok := parseEXIFTime(cleanASCII(val)); ok {
				out.DateTaken = ts
			}
		case tagDateTime:
			if out.DateTaken.IsZero() {
				if ts, ok := parseEXIFTime(cleanASCII(val)); ok {
					out.DateTaken = ts
				}
			}
		case tagPixelXDimension:
			if v, ok := scalarInt(t, val, typ); ok {
				out.Width = v
			}
		case tagPixelYDimension:
			if v, ok := scalarInt(t, val, typ); ok {
				out.Height = v
			}
		}
	}
}

// entryValue devuelve los bytes del valor de una entrada, esté inline (<=4
// bytes) o apuntado por offset.
func entryValue(t *tiff, entry int, typ uint16, count uint32) ([]byte, bool) {
	ts := typeSize(typ)
	if ts == 0 {
		return nil, false
	}

	// Cota dura antes de multiplicar: un count corrupto puede desbordar.
	if count > uint32(len(t.data)) {
		return nil, false
	}
	size := int(count) * ts
	if size <= 0 || size > len(t.data) {
		return nil, false
	}

	if size <= 4 {
		if entry+8+size > len(t.data) {
			return nil, false
		}
		return t.data[entry+8 : entry+8+size], true
	}

	off, ok := t.u32(entry + 8)
	if !ok {
		return nil, false
	}
	start := int(off)
	if start < 0 || start+size > len(t.data) {
		return nil, false
	}
	return t.data[start : start+size], true
}

// scalarInt lee un SHORT o LONG suelto.
func scalarInt(t *tiff, val []byte, typ uint16) (int, bool) {
	switch typ {
	case 3: // SHORT
		if len(val) < 2 {
			return 0, false
		}
		return int(t.bo.Uint16(val[:2])), true
	case 4: // LONG
		if len(val) < 4 {
			return 0, false
		}
		return int(t.bo.Uint32(val[:4])), true
	}
	return 0, false
}

// cleanASCII recorta en el primer NUL y descarta lo no imprimible.
func cleanASCII(b []byte) string {
	if i := indexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	var sb strings.Builder
	for _, c := range b {
		if c >= 0x20 && c < 0x7F {
			sb.WriteByte(c)
		}
	}
	return strings.TrimSpace(sb.String())
}

// decodeUCS2 convierte los tags XP* de Windows (UTF-16LE) a string.
func decodeUCS2(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	units := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u := binary.LittleEndian.Uint16(b[i : i+2])
		if u == 0 {
			break
		}
		units = append(units, u)
	}
	return strings.TrimSpace(string(utf16.Decode(units)))
}

func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

// parseEXIFTime acepta el formato EXIF estándar y rechaza fechas imposibles,
// que en datos corruptos aparecen constantemente.
func parseEXIFTime(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	ts, err := time.Parse("2006:01:02 15:04:05", s)
	if err != nil {
		return time.Time{}, false
	}
	if ts.Year() < 1990 || ts.After(time.Now().AddDate(1, 0, 0)) {
		return time.Time{}, false
	}
	return ts, true
}
