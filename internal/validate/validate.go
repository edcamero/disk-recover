// Package validate comprueba que un archivo recuperado no solo TIENE la forma
// de su formato, sino que su contenido es coherente.
//
// Es la respuesta al fallo mas grave del carving por firmas: un archivo
// fragmentado se extrae como cabecera + datos de OTRO archivo + cola, y el
// resultado tiene la firma de apertura, la de cierre y un tamano plausible. Sin
// esta capa, el usuario recibe archivos corruptos indistinguibles de los buenos.
//
// Que senal usar no fue una suposicion. Se midio sobre un JPEG real contaminado
// de dos formas distintas:
//
//	senal                         valido   relleno 0x5A   ruido aleatorio
//	estructura (SOI/EOI)          ok       NO DETECTA     NO DETECTA
//	rachas de bytes identicos      50      detecta        NO DETECTA
//	decodificacion completa       ok       FALLA          FALLA
//
// Solo decodificar detecta los dos casos. Las comprobaciones baratas se
// conservan porque siguen aportando cuando decodificar no es viable.
package validate

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// Veredicto de una validacion.
const (
	// Valido: el contenido se comprobo y es coherente.
	Valido = "valido"
	// Corrupto: el contenido se comprobo y NO es coherente.
	Corrupto = "corrupto"
	// SinComprobar: no habia forma de comprobarlo (formato sin validador,
	// archivo demasiado grande para decodificar). No es lo mismo que valido.
	SinComprobar = "sin_comprobar"
)

// Result es el veredicto sobre un archivo.
type Result struct {
	Estado string  `json:"estado"`           // Valido | Corrupto | SinComprobar
	Score  float64 `json:"score"`            // 0..1 de integridad estructural
	Metodo string  `json:"metodo"`           // como se comprobo
	Motivo string  `json:"motivo,omitempty"` // por que fallo, si fallo
}

// OK indica si el archivo se puede entregar como bueno.
func (r Result) OK() bool { return r.Estado == Valido }

// Options controla el coste de la validacion.
type Options struct {
	// Profundo activa la decodificacion completa, que es la unica comprobacion
	// que detecta contaminacion de alta entropia. Activada por defecto: el
	// coste es por archivo recuperado, no por byte escaneado.
	Profundo bool

	// MaxPixeles acota la decodificacion. Una imagen de 4000x3000 ocupa unos
	// 18 MB decodificada; sin tope, una cabecera corrupta que declare
	// 60000x60000 pediria gigabytes. 0 usa el valor por defecto.
	MaxPixeles int
}

// DefaultMaxPixeles: 50 megapixeles cubre cualquier camara de consumo y acota
// la decodificacion a ~75 MB.
const DefaultMaxPixeles = 50 << 20

// DefaultOptions son las opciones recomendadas.
func DefaultOptions() Options {
	return Options{Profundo: true, MaxPixeles: DefaultMaxPixeles}
}

func (o Options) maxPixeles() int {
	if o.MaxPixeles <= 0 {
		return DefaultMaxPixeles
	}
	return o.MaxPixeles
}

// Validator comprueba un formato concreto.
type Validator interface {
	// Validate recibe el archivo ya extraido. Debe ser tolerante: los datos
	// vienen de un disco danado y cualquier campo puede ser absurdo.
	Validate(path string, opts Options) Result
}

// validators indexa por nombre de firma (el campo Name de signatures.Signature).
var validators = map[string]Validator{
	"jpeg": jpegValidator{},
	"png":  pngValidator{},
	"gif":  gifValidator{},
	"pdf":  pdfValidator{},
	"zip":  zipValidator{},
}

// File valida el archivo en path segun el tipo de firma que lo identifico.
//
// Un tipo sin validador devuelve SinComprobar, no Valido: no se puede afirmar
// que algo esta intacto solo porque no se sabe mirarlo.
func File(path, tipo string, opts Options) Result {
	v, ok := validators[strings.ToLower(tipo)]
	if !ok {
		return Result{
			Estado: SinComprobar,
			Score:  0.5,
			Metodo: "ninguno",
			Motivo: fmt.Sprintf("no hay validador para %q", tipo),
		}
	}
	return v.Validate(path, opts)
}

// Soportado indica si existe validador para un tipo.
func Soportado(tipo string) bool {
	_, ok := validators[strings.ToLower(tipo)]
	return ok
}

// Tipos devuelve los tipos con validador, ordenados para salida estable.
func Tipos() []string {
	out := make([]string, 0, len(validators))
	for k := range validators {
		out = append(out, k)
	}
	// Orden de insercion no garantizado en un map: ordenar para reproducibilidad.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// =========================================================================
// Utilidades compartidas
// =========================================================================

// abrir abre el archivo y devuelve tambien su tamano.
func abrir(path string) (*os.File, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, err
	}
	return f, info.Size(), nil
}

// maxRunLength devuelve la racha mas larga de bytes identicos.
//
// Es una senal barata de contaminacion por datos de baja entropia: los datos
// comprimidos de una imagen real no producen rachas largas. No detecta
// contaminacion de alta entropia, para eso hace falta decodificar.
func maxRunLength(r io.Reader, limite int) (int, error) {
	buf := make([]byte, 32<<10)
	var (
		mejor int
		run   int
		last  byte
		first = true
	)

	for {
		n, err := r.Read(buf)
		for _, b := range buf[:n] {
			if !first && b == last {
				run++
				if run > mejor {
					mejor = run
					if limite > 0 && mejor >= limite {
						return mejor, nil // ya basta para decidir
					}
				}
			} else {
				run, last, first = 1, b, false
			}
		}
		if err == io.EOF {
			return mejor, nil
		}
		if err != nil {
			return mejor, err
		}
	}
}
