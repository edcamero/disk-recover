package namerecovery

import (
	"bytes"
	"encoding/binary"
	"strings"
	"unicode/utf16"
)

// Fuente 1: metadatos incrustados en el propio archivo.
//
// Varios programas dejan el nombre original dentro del archivo: Lightroom y
// Photoshop escriben xmpMM:PreservedFileName, Windows escribe XPTitle en el
// EXIF, y muchos flujos de escaneo rellenan dc:title. Cuando aparece, es la
// fuente más fiable que hay, porque viaja dentro del archivo y no depende de
// que sobreviva ninguna estructura del sistema de archivos.

// nameFromMetadata prueba XMP primero (suele traer el nombre literal) y después
// los campos de texto del EXIF.
func nameFromMetadata(header []byte) string {
	if name := nameFromXMP(header); name != "" {
		return name
	}
	return nameFromEXIFText(header)
}

// xmpNameTags son las etiquetas XMP que suelen contener un nombre de archivo,
// en orden de fiabilidad.
var xmpNameTags = []string{
	"xmpMM:PreservedFileName",
	"photoshop:LegacyIPTCDigest",
	"dc:title",
	"tiff:DocumentName",
}

// nameFromXMP busca el paquete XMP y extrae la primera etiqueta útil.
func nameFromXMP(data []byte) string {
	start := bytes.Index(data, []byte("<x:xmpmeta"))
	if start < 0 {
		start = bytes.Index(data, []byte("<?xpacket"))
	}
	if start < 0 {
		return ""
	}

	end := bytes.Index(data[start:], []byte("</x:xmpmeta>"))
	if end < 0 {
		// Paquete truncado: nos quedamos con un trozo acotado.
		end = len(data) - start
		if end > 128<<10 {
			end = 128 << 10
		}
	}
	packet := string(data[start : start+end])

	for _, tag := range xmpNameTags {
		if tag == "photoshop:LegacyIPTCDigest" {
			continue // solo es un hash; queda en la lista para documentar por qué se ignora
		}
		if v := extractXMLValue(packet, tag); v != "" {
			if looksLikeFilename(v) {
				return v
			}
		}
	}
	return ""
}

// extractXMLValue saca el contenido de <tag>...</tag> o del atributo tag="...".
// No es un parser XML: es deliberadamente tolerante porque el paquete puede
// venir truncado a la mitad.
func extractXMLValue(doc, tag string) string {
	// Forma atributo: tag="valor"
	if i := strings.Index(doc, tag+`="`); i >= 0 {
		rest := doc[i+len(tag)+2:]
		if j := strings.IndexByte(rest, '"'); j > 0 {
			return strings.TrimSpace(rest[:j])
		}
	}

	// Forma elemento: <tag>valor</tag>, posiblemente con rdf:Alt/rdf:li dentro.
	open := "<" + tag
	i := strings.Index(doc, open)
	if i < 0 {
		return ""
	}
	rest := doc[i:]
	closeIdx := strings.Index(rest, "</"+tag+">")
	if closeIdx < 0 {
		return ""
	}
	inner := rest[:closeIdx]

	// Quedarnos con el último bloque de texto entre '>' y el final.
	if k := strings.LastIndex(inner, ">"); k >= 0 && k+1 < len(inner) {
		return strings.TrimSpace(inner[k+1:])
	}
	return ""
}

// nameFromEXIFText busca en los campos de texto del EXIF (XPTitle,
// ImageDescription, DocumentName) algo que parezca un nombre de archivo.
//
// Se hace por barrido de la firma "Exif\0\0" y búsqueda directa de los tags en
// lugar de reparsear el TIFF: aquí solo queremos cadenas, y el clasificador ya
// tiene el parser completo para lo demás.
func nameFromEXIFText(data []byte) string {
	idx := bytes.Index(data, []byte("Exif\x00\x00"))
	if idx < 0 {
		return ""
	}
	tiffStart := idx + 6
	if tiffStart+8 > len(data) {
		return ""
	}
	block := data[tiffStart:]

	var bo binary.ByteOrder
	switch {
	case block[0] == 'I' && block[1] == 'I':
		bo = binary.LittleEndian
	case block[0] == 'M' && block[1] == 'M':
		bo = binary.BigEndian
	default:
		return ""
	}
	if bo.Uint16(block[2:4]) != 42 {
		return ""
	}

	ifd0 := int(bo.Uint32(block[4:8]))
	for _, tag := range []uint16{0x9C9B /* XPTitle */, 0x010E /* ImageDescription */, 0x010D /* DocumentName */} {
		if v := findTagString(block, bo, ifd0, tag); looksLikeFilename(v) {
			return v
		}
	}
	return ""
}

// findTagString busca un tag concreto en un IFD y devuelve su valor textual.
// Todas las lecturas están acotadas: los datos vienen de un disco corrupto.
func findTagString(block []byte, bo binary.ByteOrder, ifdOff int, want uint16) string {
	if ifdOff <= 0 || ifdOff+2 > len(block) {
		return ""
	}
	count := int(bo.Uint16(block[ifdOff : ifdOff+2]))
	if count > 512 {
		count = 512
	}

	for i := 0; i < count; i++ {
		entry := ifdOff + 2 + i*12
		if entry+12 > len(block) {
			return ""
		}
		tag := bo.Uint16(block[entry : entry+2])
		if tag != want {
			continue
		}

		typ := bo.Uint16(block[entry+2 : entry+4])
		n := int(bo.Uint32(block[entry+4 : entry+8]))
		if n <= 0 || n > len(block) {
			return ""
		}

		unit := 1
		if typ == 3 {
			unit = 2
		}
		size := n * unit
		if size <= 0 || size > len(block) {
			return ""
		}

		var val []byte
		if size <= 4 {
			if entry+8+size > len(block) {
				return ""
			}
			val = block[entry+8 : entry+8+size]
		} else {
			off := int(bo.Uint32(block[entry+8 : entry+12]))
			if off < 0 || off+size > len(block) {
				return ""
			}
			val = block[off : off+size]
		}

		if want == 0x9C9B {
			return decodeUTF16LE(val)
		}
		return cleanText(val)
	}
	return ""
}

func decodeUTF16LE(b []byte) string {
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

func cleanText(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return strings.TrimSpace(string(b))
}
