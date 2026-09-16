// Package manifest lleva el registro de lo que se ha recuperado.
//
// Resuelve tres carencias a la vez:
//
//   - Trazabilidad: responde "de donde salio este archivo y como de fiable es".
//   - Reproducibilidad: dos ejecuciones sobre la misma imagen producen
//     manifiestos comparables, asi que se pueden contrastar versiones.
//   - Reanudacion: al llevar el offset de cada archivo, un escaneo interrumpido
//     sabe donde continuar sin repetir trabajo.
//
// El formato es JSONL —un objeto JSON por linea— y no un unico documento JSON,
// precisamente por lo tercero: cada linea se escribe y se sincroniza en cuanto
// el archivo esta a salvo, de modo que un corte de energia deja un manifiesto
// truncado pero valido hasta la ultima linea completa. Un array JSON habria que
// cerrarlo, y un corte lo dejaria irrecuperable.
package manifest

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Version del formato. Cambiarla obliga a revisar los lectores.
const Version = 1

// Header es la primera linea del manifiesto: describe la ejecucion.
type Header struct {
	Tipo        string    `json:"tipo"` // siempre "header"
	Version     int       `json:"version"`
	Iniciado    time.Time `json:"iniciado"`
	Origen      string    `json:"origen"`
	OrigenBytes int64     `json:"origen_bytes"`
	Destino     string    `json:"destino"`
	Modo        string    `json:"modo"`
	Herramienta string    `json:"herramienta"`
}

// Entry es una linea por archivo recuperado.
type Entry struct {
	Tipo string    `json:"tipo"` // siempre "archivo"
	TS   time.Time `json:"ts"`

	// Procedencia: donde estaba en el origen.
	Offset int64  `json:"offset"`
	Size   int64  `json:"size"`
	Metodo string `json:"metodo"` // "carve" o "fs"

	// Identidad.
	Formato string `json:"formato"`          // firma que lo identifico
	SHA256  string `json:"sha256,omitempty"` // contenido

	// Veredictos.
	Integridad    float64 `json:"integridad"`             // 0..1
	Validacion    string  `json:"validacion"`             // valido | corrupto | sin_comprobar
	ValidMetodo   string  `json:"valid_metodo,omitempty"` // como se comprobo
	ValidMotivo   string  `json:"valid_motivo,omitempty"` // por que fallo
	Categoria     string  `json:"categoria,omitempty"`    // photo, icon...
	EsUsuario     bool    `json:"es_usuario"`
	FooterHallado bool    `json:"footer_hallado"`

	// Resultado.
	Destino  string `json:"destino,omitempty"`  // ruta final, vacia si se descarto
	Descarte string `json:"descarte,omitempty"` // motivo si no se conservo
}

// Footer cierra el manifiesto con el resumen.
type Footer struct {
	Tipo        string       `json:"tipo"` // siempre "footer"
	Terminado   time.Time    `json:"terminado"`
	Duracion    string       `json:"duracion"`
	Completado  bool         `json:"completado"` // false si se interrumpio
	Archivos    int          `json:"archivos"`
	Bytes       int64        `json:"bytes"`
	Descartados int          `json:"descartados"`
	Corruptos   int          `json:"corruptos"`
	Ilegibles   []RegionJSON `json:"regiones_ilegibles,omitempty"`
}

// RegionJSON describe un tramo del origen que no se pudo leer.
type RegionJSON struct {
	Offset int64 `json:"offset"`
	Length int64 `json:"length"`
}

// Writer escribe el manifiesto de forma incremental.
//
// Es seguro para uso concurrente: aunque hoy el escaneo es monohilo, el
// manifiesto es justo la pieza que habria que compartir si algun dia se
// paraleliza, y un mutex aqui cuesta nada frente a una escritura en disco.
type Writer struct {
	mu      sync.Mutex
	f       *os.File
	bw      *bufio.Writer
	inicio  time.Time
	cerrado bool

	archivos    int
	bytes       int64
	descartados int
	corruptos   int
}

// Create abre un manifiesto nuevo en destDir y escribe su cabecera.
func Create(destDir string, h Header) (*Writer, error) {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return nil, fmt.Errorf("no se pudo crear %s: %w", destDir, err)
	}

	path := filepath.Join(destDir, Nombre)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, fmt.Errorf("no se pudo crear el manifiesto: %w", err)
	}

	h.Tipo = "header"
	h.Version = Version
	if h.Iniciado.IsZero() {
		h.Iniciado = time.Now().UTC()
	}

	w := &Writer{f: f, bw: bufio.NewWriter(f), inicio: time.Now()}
	if err := w.escribir(h); err != nil {
		f.Close()
		return nil, err
	}
	return w, nil
}

// Nombre del archivo de manifiesto dentro del directorio de salida.
const Nombre = "manifiesto.jsonl"

// Append reabre un manifiesto existente para continuar escribiendo en el.
//
// Se usa al reanudar: las entradas ya registradas se conservan y las nuevas se
// anaden al final. Los contadores arrancan desde lo que ya habia, para que el
// resumen final describa el trabajo COMPLETO y no solo el ultimo tramo.
//
// Si la ultima linea quedo a medias por un corte, se recorta antes de seguir:
// escribir detras de una linea rota produciria una linea sintacticamente
// invalida en medio del archivo, y eso si rompe la lectura.
func Append(destDir string, previo *Resumen) (*Writer, error) {
	path := filepath.Join(destDir, Nombre)

	if err := recortarLineaIncompleta(path); err != nil {
		return nil, err
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("no se pudo reabrir el manifiesto: %w", err)
	}

	w := &Writer{f: f, bw: bufio.NewWriter(f), inicio: time.Now()}
	for _, e := range previo.Entradas {
		if e.Descarte != "" {
			w.descartados++
		} else {
			w.archivos++
			w.bytes += e.Size
		}
		if e.Validacion == "corrupto" {
			w.corruptos++
		}
	}
	return w, nil
}

// colaMaxLinea acota cuanto se retrocede buscando el ultimo salto de linea.
//
// Una entrada del manifiesto ronda los 400 bytes; 64 KB da margen de sobra
// incluso para una con rutas y motivos de error muy largos.
const colaMaxLinea = 64 << 10

// recortarLineaIncompleta deja el archivo terminado en un salto de linea,
// descartando cualquier resto parcial del final.
//
// Solo toca la COLA del archivo. La version anterior hacia os.ReadFile seguido
// de os.WriteFile, es decir, cargaba el manifiesto entero en memoria y lo
// reescribia: con 386 bytes por entrada, un disco del que se recuperan un
// millon de archivos da un manifiesto de 386 MB, y eso ocurriria en CADA
// reanudacion. Truncar en su lugar es O(1) y no asigna nada apreciable.
func recortarLineaIncompleta(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return err
	}
	size := info.Size()
	if size == 0 {
		return nil
	}

	ventana := int64(colaMaxLinea)
	if ventana > size {
		ventana = size
	}
	buf := make([]byte, ventana)
	if _, err := f.ReadAt(buf, size-ventana); err != nil && err != io.EOF {
		return err
	}

	if buf[len(buf)-1] == '\n' {
		return nil // ya termina limpio
	}

	// Buscar hacia atras el ultimo salto de linea dentro de la ventana.
	corte := int64(-1)
	for i := len(buf) - 1; i >= 0; i-- {
		if buf[i] == '\n' {
			corte = size - ventana + int64(i) + 1
			break
		}
	}
	if corte < 0 {
		// Ni un salto de linea en 64 KB: el archivo no tiene forma de
		// manifiesto. Truncar entero seria destruir datos que quiza sirvan, asi
		// que se prefiere fallar y que el llamante decida.
		return fmt.Errorf("el manifiesto %s no tiene ninguna linea completa en sus ultimos %d bytes",
			path, ventana)
	}

	return f.Truncate(corte)
}

// Add registra un archivo recuperado y lo sincroniza a disco de inmediato.
//
// Sincronizar por archivo es deliberado: el manifiesto es el punto de control
// para reanudar, y uno que se pierde en el buffer al cortarse la luz no sirve
// de punto de control. El coste es un fsync por archivo recuperado, no por
// bloque escaneado.
func (w *Writer) Add(e Entry) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.cerrado {
		return fmt.Errorf("manifiesto ya cerrado")
	}

	e.Tipo = "archivo"
	if e.TS.IsZero() {
		e.TS = time.Now().UTC()
	}

	if err := w.escribir(e); err != nil {
		return err
	}

	switch {
	case e.Descarte != "":
		w.descartados++
	default:
		w.archivos++
		w.bytes += e.Size
	}
	if e.Validacion == "corrupto" {
		w.corruptos++
	}

	if err := w.bw.Flush(); err != nil {
		return err
	}
	return w.f.Sync()
}

// Close escribe el resumen y cierra. completado indica si el escaneo termino
// por sus medios o se interrumpio.
func (w *Writer) Close(completado bool, ilegibles []RegionJSON) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.cerrado {
		return nil
	}
	w.cerrado = true

	f := Footer{
		Tipo:        "footer",
		Terminado:   time.Now().UTC(),
		Duracion:    time.Since(w.inicio).Round(time.Millisecond).String(),
		Completado:  completado,
		Archivos:    w.archivos,
		Bytes:       w.bytes,
		Descartados: w.descartados,
		Corruptos:   w.corruptos,
		Ilegibles:   ilegibles,
	}
	if err := w.escribir(f); err != nil {
		w.f.Close()
		return err
	}

	if err := w.bw.Flush(); err != nil {
		w.f.Close()
		return err
	}
	if err := w.f.Sync(); err != nil {
		w.f.Close()
		return err
	}
	return w.f.Close()
}

// Abort cierra el manifiesto SIN escribir el resumen, dejandolo en el mismo
// estado que un corte de energia: valido hasta la ultima linea completa y
// marcado implicitamente como no terminado, porque le falta el footer.
//
// Es lo que hay que llamar cuando el proceso se rinde de una forma en la que
// escribir un resumen seria mentir sobre lo que paso.
func (w *Writer) Abort() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.cerrado {
		return nil
	}
	w.cerrado = true

	w.bw.Flush()
	w.f.Sync()
	return w.f.Close()
}

// Stats devuelve el recuento actual.
func (w *Writer) Stats() (archivos, descartados, corruptos int, bytes int64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.archivos, w.descartados, w.corruptos, w.bytes
}

func (w *Writer) escribir(v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("no se pudo serializar la entrada: %w", err)
	}
	if _, err := w.bw.Write(data); err != nil {
		return err
	}
	return w.bw.WriteByte('\n')
}

// =========================================================================
// Lectura
// =========================================================================

// Resumen es lo que se extrae de un manifiesto existente.
type Resumen struct {
	Header      Header
	Entradas    []Entry
	Footer      *Footer // nil si el escaneo no llego a terminar
	UltimoOfset int64   // mayor offset registrado: punto de reanudacion
	Truncado    bool    // hubo una linea incompleta al final
}

// Read lee un manifiesto. Tolera que la ultima linea este a medias, que es
// exactamente lo que deja un corte de energia y el caso que hay que soportar
// para poder reanudar.
func Read(path string) (*Resumen, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ReadFrom(f)
}

// ReadFrom lee un manifiesto de cualquier origen.
func ReadFrom(r io.Reader) (*Resumen, error) {
	res := &Resumen{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<20)

	for sc.Scan() {
		linea := strings.TrimSpace(sc.Text())
		if linea == "" {
			continue
		}

		// Averiguar el tipo sin deserializar dos veces la estructura completa.
		var probe struct {
			Tipo string `json:"tipo"`
		}
		if err := json.Unmarshal([]byte(linea), &probe); err != nil {
			// Linea a medias: es el final de un escaneo interrumpido.
			res.Truncado = true
			break
		}

		switch probe.Tipo {
		case "header":
			if err := json.Unmarshal([]byte(linea), &res.Header); err != nil {
				return nil, fmt.Errorf("cabecera ilegible: %w", err)
			}
		case "archivo":
			var e Entry
			if err := json.Unmarshal([]byte(linea), &e); err != nil {
				res.Truncado = true
				break
			}
			res.Entradas = append(res.Entradas, e)
			if fin := e.Offset + e.Size; fin > res.UltimoOfset {
				res.UltimoOfset = fin
			}
		case "footer":
			var fo Footer
			if err := json.Unmarshal([]byte(linea), &fo); err != nil {
				res.Truncado = true
				break
			}
			res.Footer = &fo
		}
	}

	if err := sc.Err(); err != nil {
		// Un error de lectura al final tambien indica truncamiento.
		res.Truncado = true
	}

	if res.Header.Version == 0 {
		return nil, fmt.Errorf("manifiesto sin cabecera valida")
	}
	if res.Header.Version > Version {
		return nil, fmt.Errorf("manifiesto de version %d, esta herramienta lee hasta la %d",
			res.Header.Version, Version)
	}

	return res, nil
}

// Reanudable indica si el manifiesto describe un escaneo que quedo a medias y
// se puede continuar.
func (r *Resumen) Reanudable() bool {
	return r.Footer == nil || !r.Footer.Completado
}

// Hashes devuelve el conjunto de SHA256 ya registrados, para deduplicar entre
// ejecuciones sin releer los archivos.
func (r *Resumen) Hashes() map[string]bool {
	out := make(map[string]bool, len(r.Entradas))
	for _, e := range r.Entradas {
		if e.SHA256 != "" {
			out[e.SHA256] = true
		}
	}
	return out
}
