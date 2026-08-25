package scanner

import (
	"fmt"
	"io"
	"time"
)

// Progress representa el estado actual del escaneo.
type Progress struct {
	ScannedBytes int64
	TotalBytes   int64
	Percent      float64
	SpeedMBps    float64
	ETA          time.Duration
}

// Region describe un tramo del origen que no se pudo leer.
type Region struct {
	Offset int64
	Length int64
}

// Config configura el comportamiento del escáner.
type Config struct {
	BlockSize int // Tamaño del bloque de lectura (ej: 1MB)
	Overlap   int // Superposición para no perder firmas en los bordes (ej: 64KB)

	// SectorSize es el salto al encontrar una región ilegible. 512 por defecto.
	SectorSize int
}

// Scanner lee un dispositivo de bloque con una ventana deslizante.
//
// NO es seguro para uso concurrente: Scan debe ejecutarse desde una sola
// goroutine y los setters llamarse antes de arrancar. Antes había aquí un
// sync.Mutex que solo envolvía la llamada al callback de progreso mientras los
// setters escribían los campos sin protección: no protegía nada y sugería una
// garantía que el tipo no da.
type Scanner struct {
	src        io.ReaderAt
	size       int64
	config     Config
	onProgress func(Progress)
	cancel     <-chan struct{}

	// start es el offset desde el que arrancar. Distinto de cero al reanudar
	// un escaneo interrumpido.
	start int64

	// unreadable acumula los tramos que no se pudieron leer, para poder
	// informar al final de qué se perdió y dónde.
	unreadable []Region
}

// NewScanner crea una nueva instancia de Scanner.
func NewScanner(src io.ReaderAt, size int64, cfg Config) *Scanner {
	if cfg.BlockSize <= 0 {
		cfg.BlockSize = 1 << 20 // 1 MB
	}
	if cfg.Overlap <= 0 {
		cfg.Overlap = 64 << 10 // 64 KB
	}
	if cfg.SectorSize <= 0 {
		cfg.SectorSize = 512
	}
	// El overlap no puede alcanzar al bloque: si lo hiciera, el avance por
	// iteración sería cero y el escaneo no progresaría.
	if cfg.Overlap >= cfg.BlockSize {
		cfg.Overlap = cfg.BlockSize / 2
	}

	return &Scanner{src: src, size: size, config: cfg}
}

// SetProgressCallback establece la función de reporte de progreso.
// Llamar antes de Scan.
func (s *Scanner) SetProgressCallback(cb func(Progress)) {
	s.onProgress = cb
}

// SetCancelChannel establece un canal para cancelar el escaneo (ej: SIGINT).
// Llamar antes de Scan.
func (s *Scanner) SetCancelChannel(cancel <-chan struct{}) {
	s.cancel = cancel
}

// Unreadable devuelve los tramos que no se pudieron leer durante el escaneo.
func (s *Scanner) Unreadable() []Region {
	out := make([]Region, len(s.unreadable))
	copy(out, s.unreadable)
	return out
}

// Scan recorre todo el origen y ejecuta el callback por cada bloque de datos.
// El callback recibe el offset absoluto en el disco y el slice de bytes.
//
// El slice es un buffer reutilizado entre iteraciones: el callback no debe
// retenerlo más allá de su propia ejecución.
func (s *Scanner) Scan(callback func(offset int64, data []byte) error) error {
	if s.size <= 0 {
		return fmt.Errorf("el tamaño del origen es %d", s.size)
	}

	// Buffer único reutilizable, para no generar presión de GC asignando un
	// bloque de 1 MB por iteración.
	buf := make([]byte, s.config.BlockSize+s.config.Overlap)

	// Al reanudar se arranca desde donde quedó el escaneo anterior, retrocediendo
	// el solape: una firma que empezara justo antes del punto de corte se
	// perdería si se empezara exactamente ahí.
	offset := s.start
	if offset > 0 {
		offset -= int64(s.config.Overlap)
		if offset < 0 {
			offset = 0
		}
	}

	startTime := time.Now()
	lastProgressTime := startTime

	for offset < s.size {
		if s.cancelled() {
			return fmt.Errorf("escaneo cancelado por el usuario")
		}

		// Recortar la lectura al final del origen.
		toRead := int64(len(buf))
		if offset+toRead > s.size {
			toRead = s.size - offset
		}

		n, err := s.src.ReadAt(buf[:toRead], offset)

		if n > 0 {
			if cbErr := callback(offset, buf[:n]); cbErr != nil {
				return cbErr
			}
		}

		advance, done := s.step(offset, n, toRead, err)
		if done {
			break
		}
		offset += advance

		if s.onProgress != nil {
			if now := time.Now(); now.Sub(lastProgressTime) >= time.Second {
				s.reportProgress(offset, startTime, now)
				lastProgressTime = now
			}
		}
	}

	if s.onProgress != nil {
		s.reportProgress(s.size, startTime, time.Now())
	}

	return nil
}

// step decide cuánto avanzar tras una lectura, y si el escaneo ha terminado.
//
// El caso importante es la lectura corta. Un dispositivo de bloque con un
// sector defectuoso devuelve n < len(buf) junto con un error: es el
// comportamiento normal en el escenario para el que existe esta herramienta.
// La versión anterior avanzaba BlockSize sin mirar n y descartaba el error, así
// que los bytes entre offset+n y offset+BlockSize NO se escaneaban nunca y
// nadie se enteraba. En un disco dañado eso significa perder justo las regiones
// que rodean al daño.
func (s *Scanner) step(offset int64, n int, toRead int64, err error) (advance int64, done bool) {
	blockSize := int64(s.config.BlockSize)
	overlap := int64(s.config.Overlap)
	sector := int64(s.config.SectorSize)

	// Nada leído.
	if n == 0 {
		if err == io.EOF || offset+toRead >= s.size {
			return 0, true
		}
		// Región ilegible: saltar al siguiente límite de sector y reintentar.
		// Antes esto abortaba el escaneo entero, y con err == nil producía
		// además un mensaje corrupto ("%!w(<nil>)").
		//
		// El salto se ALINEA al sector. Avanzar un sector entero desde un
		// offset arbitrario sobrepasa el final de la zona mala y se lleva por
		// delante bytes legibles: si el daño acaba en 2048 y estamos en 2012,
		// un salto de 512 aterriza en 2524 y se pierden 476 bytes buenos.
		skip := sector - offset%sector
		s.markUnreadable(offset, skip)
		return skip, false
	}

	// Se leyó el bloque completo: avance normal, dejando el solape.
	if int64(n) >= blockSize {
		if offset+blockSize >= s.size {
			return 0, true
		}
		return blockSize, false
	}

	// Lectura corta.
	if err != nil && err != io.EOF {
		s.markUnreadable(offset+int64(n), sector)
	}
	if offset+int64(n) >= s.size {
		return 0, true // era el final del origen
	}

	// Avanzar por lo realmente leído, conservando el solape para no perder una
	// firma a caballo del corte.
	advance = int64(n) - overlap
	if advance <= 0 {
		advance = int64(n)
	}
	// Garantizar progreso: sin esto un origen que devuelva siempre lecturas
	// diminutas podría no avanzar nunca.
	if advance <= 0 {
		advance = sector
	}
	return advance, false
}

func (s *Scanner) markUnreadable(offset, length int64) {
	// Fusionar con el tramo anterior si es contiguo, para no acumular un
	// registro por sector en un disco muy dañado.
	if k := len(s.unreadable) - 1; k >= 0 {
		if last := &s.unreadable[k]; last.Offset+last.Length == offset {
			last.Length += length
			return
		}
	}
	s.unreadable = append(s.unreadable, Region{Offset: offset, Length: length})
}

func (s *Scanner) cancelled() bool {
	if s.cancel == nil {
		return false
	}
	select {
	case <-s.cancel:
		return true
	default:
		return false
	}
}

func (s *Scanner) reportProgress(current int64, start, now time.Time) {
	// Un escaneo muy rápido puede dar elapsed == 0, y entonces la velocidad
	// sale +Inf (o NaN si current también es 0) y la UI muestra "NaN MB/s".
	elapsed := now.Sub(start).Seconds()
	if elapsed < 0.001 {
		elapsed = 0.001
	}

	speedBytesPerSec := float64(current) / elapsed

	var eta time.Duration
	if speedBytesPerSec > 0 {
		seconds := float64(s.size-current) / speedBytesPerSec
		if seconds > 0 && seconds < float64(maxETASeconds) {
			eta = time.Duration(seconds * float64(time.Second))
		}
	}

	s.onProgress(Progress{
		ScannedBytes: current,
		TotalBytes:   s.size,
		Percent:      float64(current) / float64(s.size) * 100.0,
		SpeedMBps:    speedBytesPerSec / (1024 * 1024),
		ETA:          eta,
	})
}

// maxETASeconds es el tope de segundos que cabe en un time.Duration
// (int64 de nanosegundos) sin desbordar.
const maxETASeconds = 1 << 33

// SetStartOffset indica desde qué punto del origen arrancar el escaneo.
//
// Se usa al reanudar: el manifiesto de una ejecución interrumpida dice hasta
// dónde se llegó, y repetir ese trabajo en un disco de 2 TB cuesta horas. Scan
// retrocede el solape por su cuenta, así que basta con pasar el último offset
// procesado.
func (s *Scanner) SetStartOffset(offset int64) {
	if offset < 0 {
		offset = 0
	}
	s.start = offset
}
