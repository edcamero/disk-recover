package signatures

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/edcamero/disk-recover/pkg/magic"
)

// Registry es el registro central de todas las firmas conocidas.
// Es seguro para consultas concurrentes desde varias goroutines.
//
// Los índices auxiliares guardan posiciones dentro del slice, no punteros a sus
// elementos. Guardar &r.signatures[i] parece natural pero está roto: en cuanto
// append supera la capacidad reasigna el array subyacente, y todos los punteros
// almacenados antes quedan apuntando al array viejo. Con las 8 firmas por
// defecto y capacidad inicial 0, el slice crece 1→2→4→8: cuatro reasignaciones,
// tras las cuales la mayoría de los punteros del índice están desligados.
type Registry struct {
	mu         sync.RWMutex
	signatures []Signature
	byName     map[string]int
	byExt      map[string][]int
}

// NewRegistry crea un registro vacío.
func NewRegistry() *Registry {
	return &Registry{
		signatures: make([]Signature, 0, len(DefaultSignatures)),
		byName:     make(map[string]int),
		byExt:      make(map[string][]int),
	}
}

// DefaultRegistry devuelve un registro con las firmas por defecto.
func DefaultRegistry() *Registry {
	r := NewRegistry()
	for _, sig := range DefaultSignatures {
		if err := r.Register(sig); err != nil {
			// Las firmas por defecto son código, no datos de entrada: si una es
			// inválida es un error de programación y hay que verlo de inmediato,
			// no descubrirlo cuando el carving no encuentra nada.
			panic(fmt.Sprintf("firma por defecto inválida %q: %v", sig.Name, err))
		}
	}
	return r
}

// Register añade una nueva firma al registro.
func (r *Registry) Register(sig Signature) error {
	if sig.Name == "" {
		return fmt.Errorf("firma inválida: Name es obligatorio")
	}
	if sig.Header.Len() == 0 {
		return fmt.Errorf("firma %q inválida: Header es obligatorio", sig.Name)
	}
	if sig.MaxSize < 0 {
		return fmt.Errorf("firma %q inválida: MaxSize negativo", sig.Name)
	}

	sig.Name = strings.ToLower(sig.Name)
	sig.Extension = strings.ToLower(sig.Extension)
	if sig.Extension != "" && !strings.HasPrefix(sig.Extension, ".") {
		sig.Extension = "." + sig.Extension
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.byName[sig.Name]; exists {
		return fmt.Errorf("firma %q ya registrada", sig.Name)
	}

	idx := len(r.signatures)
	r.signatures = append(r.signatures, sig)
	r.byName[sig.Name] = idx
	r.byExt[sig.Extension] = append(r.byExt[sig.Extension], idx)

	return nil
}

// GetByName busca una firma por su nombre.
//
// Devuelve una copia, no un puntero al interior del registro: entregar
// *Signature dejaba que el llamante mutara el estado compartido después de
// soltar el lock.
func (r *Registry) GetByName(name string) (Signature, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	idx, ok := r.byName[strings.ToLower(name)]
	if !ok {
		return Signature{}, false
	}
	return r.signatures[idx], true
}

// GetByExtension devuelve copias de todas las firmas con la extensión dada.
func (r *Registry) GetByExtension(ext string) []Signature {
	ext = strings.ToLower(ext)
	if ext != "" && !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	idxs := r.byExt[ext]
	out := make([]Signature, 0, len(idxs))
	for _, i := range idxs {
		out = append(out, r.signatures[i])
	}
	return out
}

// All devuelve una copia de todas las firmas registradas.
func (r *Registry) All() []Signature {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]Signature, len(r.signatures))
	copy(out, r.signatures)
	return out
}

// Count devuelve el número de firmas registradas.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.signatures)
}

// Filter devuelve las firmas que cumplen el predicado.
//
// El predicado se evalúa FUERA del lock. Llamar a código del usuario con el
// RLock tomado invita al deadlock: si el predicado consulta el registro
// (GetByName, por ejemplo) hace un RLock recursivo, y el RWMutex de Go bloquea
// a los lectores nuevos en cuanto hay un escritor esperando.
func (r *Registry) Filter(predicate func(Signature) bool) []Signature {
	snapshot := r.All()

	var out []Signature
	for _, sig := range snapshot {
		if predicate(sig) {
			out = append(out, sig)
		}
	}
	return out
}

// FilterByCategory filtra por categoría (image, video, document, archive...).
func (r *Registry) FilterByCategory(category string) []Signature {
	return r.Filter(func(s Signature) bool {
		return strings.EqualFold(s.Category, category)
	})
}

// =========================================================================
// Carga desde archivo (formato inspirado en PhotoRec/Foremost)
// =========================================================================

// LoadFromFile carga firmas adicionales desde un archivo de configuración.
// Formato soportado (una firma por bloque):
//
//	# Comentario
//	name: jpeg
//	ext: .jpg
//	category: image
//	header: ff d8 ff
//	footer: ff d9
//	maxsize: 50MB
//	---
//	name: mp4
//	header: ?? ?? ?? ?? 66 74 79 70
//	...
//
// El header acepta comodines "??" para bytes variables.
func (r *Registry) LoadFromFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("no se pudo abrir %s: %w", path, err)
	}
	defer f.Close()
	return r.LoadFromReader(f)
}

// LoadFromReader carga firmas desde cualquier io.Reader.
//
// Es transaccional: se parsea todo primero y solo se registra si el archivo
// entero es válido. Registrar sobre la marcha dejaba el registro a medio llenar
// cuando fallaba la línea 40, con un estado que el llamante no puede deshacer.
func (r *Registry) LoadFromReader(rd io.Reader) error {
	sc := bufio.NewScanner(rd)
	sc.Buffer(make([]byte, 1<<20), 1<<20)

	var (
		pending []Signature
		current *Signature
		lineNum int
	)

	flush := func() error {
		if current == nil {
			return nil
		}
		if current.Name == "" {
			return fmt.Errorf("línea %d: bloque sin 'name'", lineNum)
		}
		if current.Header.Len() == 0 {
			return fmt.Errorf("línea %d: firma %q sin 'header'", lineNum, current.Name)
		}
		pending = append(pending, *current)
		current = nil
		return nil
	}

	for sc.Scan() {
		lineNum++
		line := strings.TrimSpace(sc.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if line == "---" {
			if err := flush(); err != nil {
				return err
			}
			continue
		}

		key, value, found := strings.Cut(line, ":")
		if !found {
			return fmt.Errorf("línea %d: formato inválido (esperado 'clave: valor')", lineNum)
		}
		key = strings.TrimSpace(strings.ToLower(key))
		value = strings.TrimSpace(value)

		if current == nil {
			current = &Signature{}
		}

		switch key {
		case "name":
			current.Name = value
		case "ext", "extension":
			current.Extension = value
		case "category":
			current.Category = value
		case "header":
			m, err := magic.Parse(value)
			if err != nil {
				return fmt.Errorf("línea %d: header inválido: %w", lineNum, err)
			}
			current.Header = m
		case "footer":
			m, err := magic.Parse(value)
			if err != nil {
				return fmt.Errorf("línea %d: footer inválido: %w", lineNum, err)
			}
			current.Footer = m.Bytes()
		case "maxsize":
			size, err := parseSize(value)
			if err != nil {
				return fmt.Errorf("línea %d: maxsize inválido: %w", lineNum, err)
			}
			current.MaxSize = size
		default:
			return fmt.Errorf("línea %d: clave desconocida %q", lineNum, key)
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if err := flush(); err != nil {
		return err
	}

	// Todo válido: ahora sí se aplica.
	for _, sig := range pending {
		if err := r.Register(sig); err != nil {
			return err
		}
	}
	return nil
}

// parseSize convierte "50MB", "4GB", "1024" a bytes.
//
// Usa strconv y no fmt.Sscanf: Sscanf("%d") se detiene en el primer carácter no
// numérico sin devolver error, así que "1TB" se convertía silenciosamente en 1
// byte y limitaba el carving a nada.
func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	if s == "" {
		return 0, fmt.Errorf("tamaño vacío")
	}

	multiplier := int64(1)
	for _, suffix := range []struct {
		text string
		mult int64
	}{
		{"TB", 1 << 40}, {"GB", 1 << 30}, {"MB", 1 << 20}, {"KB", 1 << 10}, {"B", 1},
	} {
		if strings.HasSuffix(s, suffix.text) {
			multiplier = suffix.mult
			s = strings.TrimSpace(strings.TrimSuffix(s, suffix.text))
			break
		}
	}

	value, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("no se pudo parsear el tamaño %q: %w", s, err)
	}
	if value < 0 {
		return 0, fmt.Errorf("tamaño negativo: %d", value)
	}
	if multiplier != 0 && value > (1<<62)/multiplier {
		return 0, fmt.Errorf("tamaño desbordado: %q", s)
	}

	return value * multiplier, nil
}
