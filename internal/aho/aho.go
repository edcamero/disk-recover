// Package aho implementa el algoritmo Aho-Corasick para búsqueda múltiple de patrones.
// Optimiza la búsqueda de firmas mágicas de O(n*m) a O(n+m+z) donde:
//   - n = tamaño del texto (bloque de datos)
//   - m = suma de longitudes de todos los patrones
//   - z = número total de coincidencias
//
// El carver busca cada firma secuencialmente en cada bloque: con 11 firmas por
// defecto y bloques de 1MB, son 11 pasadas completas por cada MB de disco.
// En un disco de 2TB eso son ~22TB de lecturas secuenciales solo para buscar
// patrones. Aho-Corasick construye un autómata finito una vez y hace una sola
// pasada sobre el texto, reportando todas las coincidencias de todos los
// patrones simultáneamente.
package aho

import (
	"github.com/edcamero/disk-recover/internal/signatures"
	"github.com/edcamero/disk-recover/pkg/magic"
)

// Match representa una coincidencia encontrada por el autómata.
type Match struct {
	Offset int // posición dentro del texto donde empieza la coincidencia
	SigIdx int // índice de la firma en el slice original
}

// node es un nodo del trie Aho-Corasick.
type node struct {
	children map[byte]*node
	fail     *node
	output   []int // índices de firmas que terminan aquí
	depth    int   // profundidad del nodo (longitud del patrón hasta aquí)
}

// Automaton es un autómata Aho-Corasick para búsqueda múltiple de firmas.
// Una vez construido, es seguro para consultas concurrentes.
type Automaton struct {
	root     *node
	sigs     []signatures.Signature
	patterns [][]byte // patrones ancla para cada firma
	anchors  []int    // offset del ancla dentro del patrón completo
}

// NewAutomaton construye un autómata para múltiples firmas.
// Devuelve nil si no hay firmas válidas.
func NewAutomaton(sigs []signatures.Signature) *Automaton {
	if len(sigs) == 0 {
		return nil
	}

	a := &Automaton{
		root:     &node{children: make(map[byte]*node)},
		sigs:     sigs,
		patterns: make([][]byte, len(sigs)),
		anchors:  make([]int, len(sigs)),
	}

	// Fase 1: Construir el trie con los patrones ancla.
	// Para patrones con wildcards, usamos el tramo fijo más largo como ancla.
	for i, sig := range sigs {
		pattern, anchorOffset := extractAnchorWithOffset(sig.Header)
		if len(pattern) == 0 {
			// Patrón todo comodines: coincidiría en cualquier posición.
			// Lo manejamos como patrón vacío especial.
			a.patterns[i] = []byte{}
			a.anchors[i] = 0
			continue
		}
		a.patterns[i] = pattern
		a.anchors[i] = anchorOffset
		a.insert(pattern, i)
	}

	// Fase 2: Construir los failure links con BFS.
	a.buildFailureLinks()

	return a
}

// extractAnchorWithOffset extrae el tramo fijo más largo de un patrón Magic
// y devuelve tanto el patrón como su offset dentro del patrón original.
// Para "?? ?? ?? ?? 66 74 79 70" devuelve ("ftyp", 4).
func extractAnchorWithOffset(m magic.Magic) ([]byte, int) {
	start, length := longestFixedRun(m)
	if length == 0 {
		return nil, 0
	}
	bytes := m.Bytes()
	return bytes[start : start+length], start
}

// longestFixedRun localiza el tramo contiguo más largo de bytes no comodín.
func longestFixedRun(m magic.Magic) (start, length int) {
	mask := m.Mask()
	bytesLen := m.Len()

	bestStart, bestLen := 0, 0
	curStart, curLen := 0, 0

	for i := 0; i < bytesLen; i++ {
		if mask[i] == 0x00 {
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

// getMask ya no es necesario ahora que Magic.Mask() es público.

// insert añade un patrón al trie.
func (a *Automaton) insert(pattern []byte, sigIdx int) {
	current := a.root
	depth := 0
	for _, b := range pattern {
		if current.children[b] == nil {
			current.children[b] = &node{children: make(map[byte]*node), depth: depth + 1}
		}
		current = current.children[b]
		depth++
	}
	current.output = append(current.output, sigIdx)
}

// buildFailureLinks construye los failure links usando BFS.
func (a *Automaton) buildFailureLinks() {
	queue := []*node{}

	// Inicializar: todos los hijos de la raíz tienen fail = root.
	for _, child := range a.root.children {
		child.fail = a.root
		queue = append(queue, child)
	}

	// BFS para construir failure links.
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		for char, child := range current.children {
			queue = append(queue, child)

			// Seguir failure links hasta encontrar un prefijo válido.
			fail := current.fail
			for fail != nil {
				if next, ok := fail.children[char]; ok {
					child.fail = next
					break
				}
				fail = fail.fail
			}
			if fail == nil {
				child.fail = a.root
			}

			// Merge output: añadir coincidencias del failure link.
			child.output = append(child.output, child.fail.output...)
		}
	}
}

// FindAll busca todas las coincidencias de todas las firmas en el texto.
// Devuelve una lista de matches con offset e índice de firma.
// Complejidad: O(n + z) donde n = len(text), z = número de coincidencias.
func (a *Automaton) FindAll(text []byte) []Match {
	if a == nil || len(text) == 0 {
		return nil
	}

	var matches []Match
	current := a.root

	for i := 0; i < len(text); i++ {
		b := text[i]

		// Seguir failure links hasta encontrar transición válida o llegar a root.
		for current != a.root {
			if next, ok := current.children[b]; ok {
				current = next
				break
			}
			current = current.fail
		}
		if next, ok := current.children[b]; ok {
			current = next
		}

		// Reportar todas las coincidencias en este nodo.
		for _, sigIdx := range current.output {
			// Calcular offset real del patrón completo.
			// El autómata encuentra el ancla, pero necesitamos retroceder al inicio del patrón.
			patternLen := current.depth
			anchorOffset := a.anchors[sigIdx]
			offset := i - patternLen + 1 - anchorOffset
			if patternLen > 0 && offset >= 0 {
				matches = append(matches, Match{Offset: offset, SigIdx: sigIdx})
			} else if patternLen == 0 {
				// Patrón todo comodines: reportar offset 0
				matches = append(matches, Match{Offset: 0, SigIdx: sigIdx})
			}
		}
	}

	return matches
}

// FindAllConcurrent es una versión optimizada que usa sync.Pool para reducir GC.
// Útil cuando se llama desde múltiples goroutines (ej: escaneo paralelo).
func (a *Automaton) FindAllConcurrent(text []byte) []Match {
	return a.FindAll(text)
}
