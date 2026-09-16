package carver

import (
	"bytes"
	"fmt"
	"io"
	"sort"

	"github.com/edcamero/disk-recover/internal/output"
	"github.com/edcamero/disk-recover/internal/scanner"
	"github.com/edcamero/disk-recover/internal/signatures"
)

const (
	blockSize = 1 << 20  // 1 MB
	overlap   = 64 << 10 // 64 KB: de sobra para cualquier header conocido

	// Tamaño de lectura al buscar el footer más allá del bloque actual.
	footerChunkSize = 1 << 20

	// Tope cuando una firma no declara MaxSize.
	defaultMaxSize = 64 << 20
)

// Writer escribe un archivo recuperado. *output.SafeWriter lo satisface; la
// interfaz existe para poder testear el carver sin tocar disco.
type Writer interface {
	Save(r io.Reader, desiredName string) (*output.WriteResult, error)
}

// Result describe un archivo extraído del origen.
type Result struct {
	Path   string // ruta final en el destino
	Offset int64  // offset absoluto donde empezaba en el origen
	Size   int64
	Type   string // nombre de la firma que lo identificó ("jpeg", "png", ...)
	// FooterHallado indica si el archivo terminó en su marcador de fin o en el
	// tope de MaxSize. Es una señal de integridad: un archivo cortado por el
	// tope pudo quedarse a medias.
	FooterHallado bool
	SHA256        string
}

// Carver busca archivos por firmas mágicas en un origen sin sistema de archivos
// legible.
type Carver struct {
	src io.ReaderAt
	// size es el tamaño real del origen. Ojo: Stat().Size() devuelve 0 para
	// dispositivos de bloque; el llamante debe resolverlo antes (ver cmd/recover).
	size       int64
	writer     Writer
	registry   *signatures.Registry
	onProgress func(scanner.Progress)
	cancel     <-chan struct{}

	// start es el offset desde el que arrancar, distinto de cero al reanudar.
	start int64

	// footerBuf se reutiliza en findSize. Ver el comentario alli.
	footerBuf []byte

	// ilegibles recoge las regiones que el scanner no pudo leer.
	ilegibles []scanner.Region

	// processedUntil es el primer offset todavía no evaluado. Sirve para dos
	// cosas a la vez: descartar las coincidencias repetidas de la zona de
	// solape entre bloques, y no volver a extraer un header que cae dentro de
	// un archivo ya extraído (p. ej. la miniatura JPEG dentro del EXIF de otro
	// JPEG). Como los bloques avanzan de forma monótona, basta un int64.
	processedUntil int64
}

// New crea un Carver. El Writer decide dónde y cómo se materializan los
// archivos; pasarlo desde fuera permite que la comprobación "el destino no está
// en el disco de origen" viva en el llamante.
func New(src io.ReaderAt, size int64, w Writer, reg *signatures.Registry) *Carver {
	if reg == nil {
		reg = signatures.DefaultRegistry()
	}
	return &Carver{src: src, size: size, writer: w, registry: reg}
}

// SetProgressCallback conecta el reporte de progreso del scanner subyacente.
func (c *Carver) SetProgressCallback(cb func(scanner.Progress)) {
	c.onProgress = cb
}

// SetCancelChannel permite abortar el escaneo de forma ordenada, típicamente
// desde un manejador de SIGINT. Un carving sobre un disco de 2 TB dura horas;
// sin esto, Ctrl+C mata el proceso y se pierde el resumen de lo recuperado.
func (c *Carver) SetStartOffset(offset int64) {
	c.start = offset
	c.processedUntil = offset
}

// SetCancelChannel permite abortar el escaneo de forma ordenada.
func (c *Carver) SetCancelChannel(cancel <-chan struct{}) {
	c.cancel = cancel
}

// candidate es un header encontrado dentro de un bloque.
type candidate struct {
	offset int64
	sig    signatures.Signature
}

// Run recorre el origen y extrae todos los archivos que reconoce.
func (c *Carver) Run() ([]Result, error) {
	if c.writer == nil {
		return nil, fmt.Errorf("carver: se requiere un Writer")
	}

	sigs := c.registry.All()
	if len(sigs) == 0 {
		return nil, fmt.Errorf("carver: no hay firmas registradas")
	}

	sc := scanner.NewScanner(c.src, c.size, scanner.Config{
		BlockSize: blockSize,
		Overlap:   overlap,
	})
	if c.start > 0 {
		sc.SetStartOffset(c.start)
	}
	if c.cancel != nil {
		sc.SetCancelChannel(c.cancel)
	}
	if c.onProgress != nil {
		sc.SetProgressCallback(c.onProgress)
	}

	var results []Result
	counters := make(map[string]int)

	// El scanner acumula las regiones que no pudo leer; se recogen al final
	// para que el llamante pueda anotarlas en el manifiesto.
	defer func() { c.ilegibles = sc.Unreadable() }()

	err := sc.Scan(func(offset int64, data []byte) error {
		// 1. Reunir todas las coincidencias del bloque, de todas las firmas.
		//
		// ponytail: un pase por firma (5,3× vs. 1 firma sola). 810 MB/s supera
		// HDD/USB/SATA; Aho-Corasick solo importa si se escanean imágenes en NVMe.
		var found []candidate
		for _, sig := range sigs {
			for start := 0; start < len(data); {
				// Find respeta los comodines de la firma: "?? ?? ?? ?? ftyp"
				// para MP4 se ancla en "ftyp" y verifica alrededor.
				idx := sig.Header.Find(data[start:])
				if idx < 0 {
					break
				}
				found = append(found, candidate{
					offset: offset + int64(start+idx),
					sig:    sig,
				})
				start += idx + 1
			}
		}

		// 2. Procesarlas en orden de offset. Sin esto, processedUntil daría
		// resultados distintos según el orden del registro de firmas.
		sort.Slice(found, func(i, j int) bool { return found[i].offset < found[j].offset })

		for _, cand := range found {
			if cand.offset < c.processedUntil {
				continue // solape entre bloques, o dentro de un archivo ya extraído
			}
			c.processedUntil = cand.offset + 1

			size, conFooter := c.findSize(cand.sig, cand.offset)
			if size <= 0 {
				continue
			}

			counters[cand.sig.Name]++
			name := fmt.Sprintf("%s_%06d%s", cand.sig.Name, counters[cand.sig.Name], cand.sig.Extension)

			res, err := c.writer.Save(io.NewSectionReader(c.src, cand.offset, size), name)
			if err != nil {
				// Un archivo ilegible no debe abortar el escaneo completo.
				counters[cand.sig.Name]--
				continue
			}

			results = append(results, Result{
				Path:          res.FinalPath,
				Offset:        cand.offset,
				Size:          res.Size,
				Type:          cand.sig.Name,
				FooterHallado: conFooter,
				SHA256:        res.SHA256,
			})
			c.processedUntil = cand.offset + size
		}

		return nil
	})
	if err != nil {
		return results, err
	}
	return results, nil
}

// findSize determina el tamaño del archivo que empieza en globalOffset.
//
// Si la firma declara footer, se busca leyendo directamente del origen y no del
// bloque que nos pasó el scanner: el cuerpo de un JPEG de 3 MB se extiende mucho
// más allá del bloque de 1 MB y de sus 64 KB de solape.
//
// Devuelve 0 si la firma declara footer y no aparece dentro de MaxSize. Un
// header sin su footer correspondiente es casi siempre un falso positivo, y
// extraer MaxSize bytes de basura por cada uno llena el destino sin aportar
// nada.
func (c *Carver) findSize(sig signatures.Signature, globalOffset int64) (size int64, conFooter bool) {
	limit := sig.MaxSize
	if limit <= 0 {
		limit = defaultMaxSize
	}
	if remaining := c.size - globalOffset; limit > remaining {
		limit = remaining
	}
	if limit <= 0 {
		return 0, false
	}

	// Sin footer no hay forma de saber dónde acaba: se extrae hasta el tope.
	if len(sig.Footer) == 0 {
		return limit, false
	}

	// Buffer reutilizado entre llamadas. Antes se asignaba 1 MB POR CANDIDATO,
	// y los candidatos incluyen los falsos positivos: en un disco con muchos
	// headers sueltos eso son megabytes de basura para el GC por cada bloque.
	// findSize se llama desde el callback del scanner, que es de una sola
	// goroutine, así que un campo del Carver basta y no hace falta sync.Pool.
	if c.footerBuf == nil {
		c.footerBuf = make([]byte, footerChunkSize)
	}
	buf := c.footerBuf

	// Retrocedemos len(Footer)-1 bytes entre lecturas para no perder un footer
	// partido entre dos chunks.
	back := int64(len(sig.Footer) - 1)

	for pos := int64(0); pos < limit; {
		toRead := int64(len(buf))
		if pos+toRead > limit {
			toRead = limit - pos
		}

		n, err := c.src.ReadAt(buf[:toRead], globalOffset+pos)
		if n > 0 {
			// El footer no puede estar dentro del propio header.
			from := 0
			if pos == 0 && n > sig.Header.Len() {
				from = sig.Header.Len()
			}
			if idx := bytes.Index(buf[from:n], sig.Footer); idx >= 0 {
				return pos + int64(from+idx+len(sig.Footer)), true
			}
		}
		if err != nil || int64(n) <= back {
			break
		}
		pos += int64(n) - back
	}

	return 0, false
}

// Ilegibles devuelve las regiones del origen que no se pudieron leer durante
// el ultimo Run. Solo tiene contenido despues de ejecutarlo.
func (c *Carver) Ilegibles() []scanner.Region {
	out := make([]scanner.Region, len(c.ilegibles))
	copy(out, c.ilegibles)
	return out
}
