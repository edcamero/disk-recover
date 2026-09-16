package magic

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
)

// Magic representa una secuencia de bytes mágicos con metadata opcional.
// Es inmutable después de la creación.
type Magic struct {
	bytes  []byte
	mask   []byte // máscara para wildcards (0xFF = byte fijo, 0x00 = ignorar)
	offset int    // offset donde debe aparecer (0 = inicio)
}

// New crea un Magic a partir de bytes fijos
func New(b []byte) Magic {
	m := Magic{bytes: make([]byte, len(b))}
	copy(m.bytes, b)
	m.mask = make([]byte, len(b))
	for i := range m.mask {
		m.mask[i] = 0xFF // todos los bytes son fijos
	}
	return m
}

// NewWithOffset crea un Magic que debe aparecer en un offset específico
func NewWithOffset(b []byte, offset int) Magic {
	m := New(b)
	m.offset = offset
	return m
}

// Parse convierte un string hexadecimal en un Magic.
// Formatos soportados:
//   - "FFD8FF"
//   - "FF D8 FF"
//   - "ff d8 ff"
//   - "FF ?? FF"  (?? = wildcard, cualquier byte)
func Parse(s string) (Magic, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Magic{}, fmt.Errorf("string vacío")
	}

	// Detectar si hay wildcards
	hasWildcard := strings.Contains(s, "??") || strings.Contains(s, "**")

	if !hasWildcard {
		// Ruta rápida: solo hex puro
		clean := strings.ReplaceAll(s, " ", "")
		clean = strings.ReplaceAll(clean, "\t", "")
		b, err := hex.DecodeString(clean)
		if err != nil {
			return Magic{}, fmt.Errorf("hex inválido: %w", err)
		}
		return New(b), nil
	}

	// Ruta con wildcards: parsear token por token.
	tokens := strings.Fields(s)

	// Forma compacta sin espacios ("FF??FF"): trocear en pares. La ruta sin
	// wildcards ya aceptaba ambas formas; sin esto, la de wildcards solo
	// funcionaba con espacios y fallaba de forma sorprendente.
	if len(tokens) == 1 && len(tokens[0]) > 2 {
		compact := tokens[0]
		if len(compact)%2 != 0 {
			return Magic{}, fmt.Errorf("longitud impar: %q", compact)
		}
		tokens = make([]string, 0, len(compact)/2)
		for i := 0; i < len(compact); i += 2 {
			tokens = append(tokens, compact[i:i+2])
		}
	}

	bytes := make([]byte, len(tokens))
	mask := make([]byte, len(tokens))

	for i, tok := range tokens {
		tok = strings.ToUpper(tok)
		if tok == "??" || tok == "**" {
			bytes[i] = 0x00
			mask[i] = 0x00 // wildcard
			continue
		}
		if len(tok) != 2 {
			return Magic{}, fmt.Errorf("token inválido en posición %d: %q", i, tok)
		}
		b, err := hex.DecodeString(tok)
		if err != nil {
			return Magic{}, fmt.Errorf("hex inválido en posición %d: %w", i, err)
		}
		bytes[i] = b[0]
		mask[i] = 0xFF
	}

	return Magic{bytes: bytes, mask: mask}, nil
}

// MustParse es como Parse pero entra en pánico si falla.
// Útil para inicializar constantes en tiempo de compilación.
func MustParse(s string) Magic {
	m, err := Parse(s)
	if err != nil {
		panic(fmt.Sprintf("magic.Parse(%q) falló: %v", s, err))
	}
	return m
}

// Bytes devuelve una copia de los bytes del magic
func (m Magic) Bytes() []byte {
	out := make([]byte, len(m.bytes))
	copy(out, m.bytes)
	return out
}

// Len devuelve la longitud del magic
func (m Magic) Len() int {
	return len(m.bytes)
}

// Mask devuelve una copia de la máscara de wildcards.
// 0xFF indica byte fijo, 0x00 indica wildcard (cualquier byte vale).
// Expuesto para permitir optimizaciones como Aho-Corasick.
func (m Magic) Mask() []byte {
	out := make([]byte, len(m.mask))
	copy(out, m.mask)
	return out
}

// Offset devuelve el offset donde debe aparecer
func (m Magic) Offset() int {
	return m.offset
}

// Hex devuelve la representación hexadecimal con espacios
// Ejemplo: "FF D8 FF E0"
func (m Magic) Hex() string {
	parts := make([]string, len(m.bytes))
	for i, b := range m.bytes {
		if m.mask[i] == 0x00 {
			parts[i] = "??"
		} else {
			parts[i] = fmt.Sprintf("%02X", b)
		}
	}
	return strings.Join(parts, " ")
}

// String es un alias de Hex para cumplir fmt.Stringer
func (m Magic) String() string {
	return m.Hex()
}

// Match verifica si el magic coincide con los datos en su offset configurado
func (m Magic) Match(data []byte) bool {
	if len(data) < m.offset+len(m.bytes) {
		return false
	}
	return m.matchAt(data, m.offset)
}

// MatchAt verifica si el magic coincide en un offset específico
func (m Magic) MatchAt(data []byte, offset int) bool {
	if offset < 0 || len(data) < offset+len(m.bytes) {
		return false
	}
	return m.matchAt(data, offset)
}

// matchAt es el núcleo de la comparación, respeta la máscara de wildcards
func (m Magic) matchAt(data []byte, offset int) bool {
	for i, b := range m.bytes {
		if m.mask[i] == 0x00 {
			continue // wildcard, cualquier byte vale
		}
		if data[offset+i] != b {
			return false
		}
	}
	return true
}

// Find busca el magic dentro de data y devuelve el offset donde aparece.
// Devuelve -1 si no se encuentra.
func (m Magic) Find(data []byte) int {
	if len(m.bytes) == 0 || len(data) < len(m.bytes) {
		return -1
	}

	hasMask := false
	for _, mk := range m.mask {
		if mk == 0x00 {
			hasMask = true
			break
		}
	}

	if !hasMask {
		// Sin wildcards: bytes.Index directo.
		return indexOfBytes(data, m.bytes)
	}

	// Con wildcards, recorrer posición a posición sería O(n*m) sobre cada byte
	// del disco. En lugar de eso anclamos: buscamos con bytes.Index el tramo
	// fijo más largo del patrón y solo verificamos el patrón completo donde ese
	// tramo aparece. Para "?? ?? ?? ?? 66 74 79 70" (MP4) el ancla es "ftyp",
	// que es raro, así que las verificaciones son poquísimas.
	start, length := m.longestFixedRun()
	if length == 0 {
		return 0 // patrón todo comodines: coincide en cualquier sitio
	}

	anchor := m.bytes[start : start+length]
	for from := 0; from <= len(data)-length; {
		idx := bytes.Index(data[from:], anchor)
		if idx < 0 {
			return -1
		}
		abs := from + idx
		if candidate := abs - start; candidate >= 0 &&
			candidate+len(m.bytes) <= len(data) &&
			m.matchAt(data, candidate) {
			return candidate
		}
		from = abs + 1
	}
	return -1
}

// longestFixedRun localiza el tramo contiguo más largo de bytes no comodín.
// Devuelve su posición dentro del patrón y su longitud (0 si todo es comodín).
func (m Magic) longestFixedRun() (start, length int) {
	bestStart, bestLen := 0, 0
	curStart, curLen := 0, 0

	for i, mk := range m.mask {
		if mk == 0x00 {
			curLen = 0
			continue
		}
		if curLen == 0 {
			curStart = i
		}
		curLen++
		if curLen > bestLen {
			bestStart, bestLen = curStart, curLen
		}
	}
	return bestStart, bestLen
}

// FindAll devuelve todos los offsets donde aparece el magic
func (m Magic) FindAll(data []byte) []int {
	var results []int
	start := 0
	for {
		idx := m.Find(data[start:])
		if idx < 0 {
			break
		}
		results = append(results, start+idx)
		start += idx + 1
	}
	return results
}

// Equal indica si dos Magic son el mismo patrón: misma longitud, mismo offset,
// mismas posiciones comodín y mismos bytes en las posiciones fijas.
//
// Ojo con la tentación de comparar bytes enmascarados (b & mask): un byte
// literal 0x00 y un comodín "??" dan ambos 0, así que New([]byte{0x00}) saldría
// igual que MustParse("??"), que son patrones muy distintos. Hay que comparar
// las máscaras por separado.
func (m Magic) Equal(other Magic) bool {
	if len(m.bytes) != len(other.bytes) || m.offset != other.offset {
		return false
	}
	for i := range m.bytes {
		if m.mask[i] != other.mask[i] {
			return false
		}
		// En una posición comodín el byte es irrelevante.
		if m.mask[i] == 0x00 {
			continue
		}
		if m.bytes[i] != other.bytes[i] {
			return false
		}
	}
	return true
}

// Contains verifica si data contiene al menos una coincidencia del magic
func (m Magic) Contains(data []byte) bool {
	return m.Find(data) >= 0
}

// =========================================================================
// Utilidades de detección genérica (como el comando `file`)
// =========================================================================

// Type representa un tipo de archivo detectado
type Type struct {
	Name      string // "jpeg", "png", etc.
	MIME      string // "image/jpeg"
	Extension string // ".jpg"
}

// knownTypes es un registro interno mínimo para detección genérica
var knownTypes = []struct {
	magic Magic
	typ   Type
}{
	{MustParse("FF D8 FF"), Type{"jpeg", "image/jpeg", ".jpg"}},
	{MustParse("89 50 4E 47 0D 0A 1A 0A"), Type{"png", "image/png", ".png"}},
	{MustParse("47 49 46 38"), Type{"gif", "image/gif", ".gif"}},
	{MustParse("25 50 44 46"), Type{"pdf", "application/pdf", ".pdf"}},
	{MustParse("50 4B 03 04"), Type{"zip", "application/zip", ".zip"}},
	{MustParse("1A 45 DF A3"), Type{"mkv", "video/x-matroska", ".mkv"}},
	{NewWithOffset([]byte("ftyp"), 4), Type{"mp4", "video/mp4", ".mp4"}},
	{New([]byte("RIFF")), Type{"riff", "application/octet-stream", ".riff"}},
	{MustParse("7F 45 4C 46"), Type{"elf", "application/x-elf", ".elf"}},
	{MustParse("CA FE BA BE"), Type{"macho", "application/x-mach-binary", ".macho"}},
}

// Detect intenta identificar el tipo de archivo a partir de sus primeros bytes.
// Devuelve el Type encontrado o un Type vacío si no se reconoce.
func Detect(data []byte) Type {
	for _, kt := range knownTypes {
		if kt.magic.Match(data) {
			return kt.typ
		}
	}
	return Type{}
}

// DetectString devuelve solo el nombre del tipo o "unknown"
func DetectString(data []byte) string {
	t := Detect(data)
	if t.Name == "" {
		return "unknown"
	}
	return t.Name
}

// =========================================================================
// Helpers internos
// =========================================================================

// indexOfBytes delega en bytes.Index.
//
// Aquí había una búsqueda ingenua escrita a mano, O(n*m). bytes.Index usa
// Rabin-Karp con rutas en ensamblador por arquitectura, y este es el bucle más
// caliente de toda la herramienta: se ejecuta sobre cada byte de un disco que
// puede tener terabytes.
func indexOfBytes(data, pattern []byte) int {
	return bytes.Index(data, pattern)
}
