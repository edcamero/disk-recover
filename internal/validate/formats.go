package validate

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"image/gif"
	"image/jpeg"
	"io"
	"os"
)

// =========================================================================
// JPEG
// =========================================================================

type jpegValidator struct{}

// maxRunJPEG es el tope de bytes identicos consecutivos que se acepta en un
// JPEG genuino.
//
// El valor NO esta elegido a ojo. Se midio sobre JPEG reales codificados por la
// biblioteca estandar, cubriendo el peor caso para esta heuristica —imagenes
// completamente uniformes, donde cabria esperar rachas largas:
//
//	contenido                    q=50  q=75  q=90  q=100
//	cielo liso 640x480             50    50    50    129
//	negro puro 640x480             50    50    50    129
//	degradado suave                50    50    50    129
//	ruido maximo                   50    50    50    129
//	uniforme 4000x3000                         50    129
//	uniforme 6000x4000                         50    129
//
// Ni el tamano ni el contenido mueven el techo: 129 a calidad 100, y viene de
// la tabla de cuantizacion, no de los datos comprimidos. Un archivo contaminado
// por fragmentacion con relleno de baja entropia da 3000 o mas. El umbral de
// 512 deja 4x de margen sobre lo observado y sigue muy por debajo del ruido.
const maxRunJPEG = 512

// Validate combina DOS senales complementarias, porque ninguna basta sola.
//
// Se midio el comportamiento de cada una sobre un JPEG real contaminado de dos
// formas distintas, que es como se manifiesta la fragmentacion:
//
//	senal                    relleno 0x5A      otro archivo comprimido
//	decodificacion completa  NO DETECTA (*)    detecta
//	racha de bytes           detecta           NO DETECTA
//
// (*) Este es el hallazgo que obligo a tener las dos. Un relleno sin ningun
// 0xFF no rompe el escapado de marcadores, asi que el decodificador lee codigos
// Huffman basura pero VALIDOS y termina sin error, produciendo una imagen
// corrupta que se daria por buena.
func (jpegValidator) Validate(path string, opts Options) Result {
	f, size, err := abrir(path)
	if err != nil {
		return Result{Estado: Corrupto, Metodo: "apertura", Motivo: err.Error()}
	}
	defer f.Close()

	if size < 4 {
		return Result{Estado: Corrupto, Metodo: "tamano", Motivo: "archivo demasiado corto"}
	}

	// Comprobaciones baratas primero: si fallan, no merece la pena decodificar.
	if r := jpegEstructura(f, size); r.Estado == Corrupto {
		return r
	}

	// Senal 1: rachas de bytes identicos. Detecta el relleno de baja entropia
	// que la decodificacion deja pasar. Se hace siempre porque es una pasada
	// secuencial sin asignaciones significativas.
	if _, err := f.Seek(0, io.SeekStart); err == nil {
		if run, err := maxRunLength(f, maxRunJPEG); err == nil && run >= maxRunJPEG {
			return Result{
				Estado: Corrupto,
				Metodo: "entropia",
				Motivo: fmt.Sprintf("racha de %d bytes identicos: relleno o datos ajenos "+
					"(un JPEG real no pasa de ~129)", run),
			}
		}
	}

	if !opts.Profundo {
		return Result{
			Estado: SinComprobar,
			Score:  0.5,
			Metodo: "estructura",
			Motivo: "validacion profunda desactivada",
		}
	}

	// DecodeConfig solo lee la cabecera: sirve para acotar el coste antes de
	// comprometerse a decodificar la imagen completa.
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return Result{Estado: Corrupto, Metodo: "seek", Motivo: err.Error()}
	}
	cfg, err := jpeg.DecodeConfig(f)
	if err != nil {
		return Result{
			Estado: Corrupto,
			Metodo: "cabecera",
			Motivo: fmt.Sprintf("cabecera ilegible: %v", err),
		}
	}

	if px := cfg.Width * cfg.Height; px <= 0 || px > opts.maxPixeles() {
		return Result{
			Estado: SinComprobar,
			Score:  0.5,
			Metodo: "estructura",
			Motivo: fmt.Sprintf("%dx%d supera el tope de decodificacion", cfg.Width, cfg.Height),
		}
	}

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return Result{Estado: Corrupto, Metodo: "seek", Motivo: err.Error()}
	}
	if _, err := jpeg.Decode(f); err != nil {
		return Result{
			Estado: Corrupto,
			Metodo: "decodificacion",
			Motivo: fmt.Sprintf("el flujo comprimido no es valido: %v", err),
		}
	}

	return Result{Estado: Valido, Score: 1, Metodo: "decodificacion"}
}

// jpegEstructura hace las comprobaciones que no requieren decodificar.
func jpegEstructura(f *os.File, size int64) Result {
	head := make([]byte, 3)
	if _, err := f.ReadAt(head, 0); err != nil {
		return Result{Estado: Corrupto, Metodo: "estructura", Motivo: "no se pudo leer la cabecera"}
	}
	if head[0] != 0xFF || head[1] != 0xD8 || head[2] != 0xFF {
		return Result{Estado: Corrupto, Metodo: "estructura", Motivo: "sin marcador SOI"}
	}

	tail := make([]byte, 2)
	if _, err := f.ReadAt(tail, size-2); err != nil {
		return Result{Estado: Corrupto, Metodo: "estructura", Motivo: "no se pudo leer el final"}
	}
	if tail[0] != 0xFF || tail[1] != 0xD9 {
		return Result{Estado: Corrupto, Metodo: "estructura", Motivo: "sin marcador EOI al final"}
	}

	return Result{Estado: Valido, Score: 0.5, Metodo: "estructura"}
}

// =========================================================================
// PNG
// =========================================================================

type pngValidator struct{}

// Validate recorre los chunks comprobando su CRC32.
//
// Es la validacion mas eficiente de todo el paquete: el formato PNG lleva un
// CRC por chunk precisamente para detectar corrupcion, asi que no hace falta
// descomprimir la imagen. Un chunk contaminado por fragmentacion falla el CRC
// de forma determinista.
func (pngValidator) Validate(path string, opts Options) Result {
	f, size, err := abrir(path)
	if err != nil {
		return Result{Estado: Corrupto, Metodo: "apertura", Motivo: err.Error()}
	}
	defer f.Close()

	firma := make([]byte, 8)
	if _, err := io.ReadFull(f, firma); err != nil {
		return Result{Estado: Corrupto, Metodo: "estructura", Motivo: "sin firma PNG"}
	}
	if !bytes.Equal(firma, []byte("\x89PNG\r\n\x1a\n")) {
		return Result{Estado: Corrupto, Metodo: "estructura", Motivo: "firma PNG incorrecta"}
	}

	var (
		offset    int64 = 8
		chunks    int
		vistoIHDR bool
		vistoIEND bool
		buf       = make([]byte, 32<<10)
	)

	for offset < size {
		cab := make([]byte, 8)
		if _, err := f.ReadAt(cab, offset); err != nil {
			return Result{
				Estado: Corrupto, Metodo: "crc",
				Motivo: fmt.Sprintf("chunk truncado en offset %d", offset),
			}
		}

		length := binary.BigEndian.Uint32(cab[0:4])
		tipo := string(cab[4:8])

		// Un length absurdo indica datos ajenos, no un PNG.
		if int64(length) > size-offset {
			return Result{
				Estado: Corrupto, Metodo: "crc",
				Motivo: fmt.Sprintf("chunk %q declara %d bytes, exceden el archivo", tipo, length),
			}
		}

		// CRC32 sobre tipo + datos, en streaming para no cargar IDAT enteros.
		h := crc32.NewIEEE()
		h.Write(cab[4:8])

		restante := int64(length)
		pos := offset + 8
		for restante > 0 {
			n := int64(len(buf))
			if n > restante {
				n = restante
			}
			leidos, err := f.ReadAt(buf[:n], pos)
			if leidos > 0 {
				h.Write(buf[:leidos])
			}
			if err != nil {
				return Result{
					Estado: Corrupto, Metodo: "crc",
					Motivo: fmt.Sprintf("lectura incompleta del chunk %q", tipo),
				}
			}
			pos += int64(leidos)
			restante -= int64(leidos)
		}

		esperado := make([]byte, 4)
		if _, err := f.ReadAt(esperado, pos); err != nil {
			return Result{
				Estado: Corrupto, Metodo: "crc",
				Motivo: fmt.Sprintf("sin CRC en el chunk %q", tipo),
			}
		}
		if got := h.Sum32(); got != binary.BigEndian.Uint32(esperado) {
			return Result{
				Estado: Corrupto, Metodo: "crc",
				Motivo: fmt.Sprintf("CRC incorrecto en el chunk %q (offset %d)", tipo, offset),
			}
		}

		chunks++
		switch tipo {
		case "IHDR":
			vistoIHDR = true
		case "IEND":
			vistoIEND = true
		}

		offset = pos + 4
		if vistoIEND {
			break
		}
		if chunks > 100000 {
			return Result{Estado: Corrupto, Metodo: "crc", Motivo: "demasiados chunks"}
		}
	}

	switch {
	case !vistoIHDR:
		return Result{Estado: Corrupto, Metodo: "crc", Motivo: "falta el chunk IHDR"}
	case !vistoIEND:
		return Result{Estado: Corrupto, Metodo: "crc", Motivo: "falta el chunk IEND: archivo truncado"}
	}

	return Result{Estado: Valido, Score: 1, Metodo: "crc"}
}

// =========================================================================
// GIF
// =========================================================================

type gifValidator struct{}

func (gifValidator) Validate(path string, opts Options) Result {
	f, _, err := abrir(path)
	if err != nil {
		return Result{Estado: Corrupto, Metodo: "apertura", Motivo: err.Error()}
	}
	defer f.Close()

	if !opts.Profundo {
		return Result{Estado: SinComprobar, Score: 0.5, Metodo: "ninguno",
			Motivo: "validacion profunda desactivada"}
	}

	if _, err := gif.DecodeAll(f); err != nil {
		return Result{Estado: Corrupto, Metodo: "decodificacion", Motivo: err.Error()}
	}
	return Result{Estado: Valido, Score: 1, Metodo: "decodificacion"}
}

// =========================================================================
// PDF
// =========================================================================

type pdfValidator struct{}

// Validate hace comprobaciones estructurales: un PDF valido empieza por %PDF-,
// termina en %%EOF y declara una tabla de referencias cruzadas con startxref.
//
// No se interpreta el contenido: hacerlo bien exige un parser completo de PDF,
// que es un proyecto en si mismo. Por eso un PDF que pase estas pruebas se
// reporta como SinComprobar y no como Valido: se sabe que la envoltura esta
// bien, no que el contenido lo este.
func (pdfValidator) Validate(path string, opts Options) Result {
	f, size, err := abrir(path)
	if err != nil {
		return Result{Estado: Corrupto, Metodo: "apertura", Motivo: err.Error()}
	}
	defer f.Close()

	if size < 32 {
		return Result{Estado: Corrupto, Metodo: "tamano", Motivo: "demasiado corto para un PDF"}
	}

	head := make([]byte, 5)
	if _, err := f.ReadAt(head, 0); err != nil || string(head) != "%PDF-" {
		return Result{Estado: Corrupto, Metodo: "estructura", Motivo: "sin cabecera %PDF-"}
	}

	// startxref y %%EOF viven al final; 2 KB cubre cualquier PDF bien formado.
	colaLen := int64(2048)
	if colaLen > size {
		colaLen = size
	}
	cola := make([]byte, colaLen)
	if _, err := f.ReadAt(cola, size-colaLen); err != nil {
		return Result{Estado: Corrupto, Metodo: "estructura", Motivo: "no se pudo leer el final"}
	}

	if !bytes.Contains(cola, []byte("%%EOF")) {
		return Result{Estado: Corrupto, Metodo: "estructura", Motivo: "sin marcador %%EOF"}
	}
	if !bytes.Contains(cola, []byte("startxref")) {
		return Result{Estado: Corrupto, Metodo: "estructura",
			Motivo: "sin startxref: la tabla de referencias no esta"}
	}

	return Result{
		Estado: SinComprobar, Score: 0.7, Metodo: "estructura",
		Motivo: "envoltura correcta; el contenido no se interpreta",
	}
}

// =========================================================================
// ZIP
// =========================================================================

type zipValidator struct{}

// Validate localiza el End Of Central Directory y comprueba que la posicion
// que declara para el directorio central cae dentro del archivo.
//
// Es una comprobacion barata que detecta el fallo tipico del carving: el
// archivo se corto antes de tiempo o se le pegaron datos ajenos, y los offsets
// dejan de cuadrar.
func (zipValidator) Validate(path string, opts Options) Result {
	f, size, err := abrir(path)
	if err != nil {
		return Result{Estado: Corrupto, Metodo: "apertura", Motivo: err.Error()}
	}
	defer f.Close()

	if size < 22 {
		return Result{Estado: Corrupto, Metodo: "tamano", Motivo: "demasiado corto para un ZIP"}
	}

	// El EOCD mide 22 bytes mas un comentario de hasta 64 KB.
	colaLen := int64(66 << 10)
	if colaLen > size {
		colaLen = size
	}
	cola := make([]byte, colaLen)
	if _, err := f.ReadAt(cola, size-colaLen); err != nil {
		return Result{Estado: Corrupto, Metodo: "estructura", Motivo: "no se pudo leer el final"}
	}

	idx := bytes.LastIndex(cola, []byte{0x50, 0x4B, 0x05, 0x06})
	if idx < 0 {
		return Result{Estado: Corrupto, Metodo: "estructura",
			Motivo: "sin End Of Central Directory: archivo truncado"}
	}
	if idx+22 > len(cola) {
		return Result{Estado: Corrupto, Metodo: "estructura", Motivo: "EOCD truncado"}
	}

	eocd := cola[idx:]
	entradas := binary.LittleEndian.Uint16(eocd[10:12])
	cdSize := int64(binary.LittleEndian.Uint32(eocd[12:16]))
	cdOffset := int64(binary.LittleEndian.Uint32(eocd[16:20]))

	if cdOffset+cdSize > size {
		return Result{
			Estado: Corrupto, Metodo: "estructura",
			Motivo: fmt.Sprintf("el directorio central (offset %d, %d bytes) cae fuera del archivo",
				cdOffset, cdSize),
		}
	}

	// La firma del directorio central debe estar donde el EOCD dice.
	if entradas > 0 {
		sig := make([]byte, 4)
		if _, err := f.ReadAt(sig, cdOffset); err != nil {
			return Result{Estado: Corrupto, Metodo: "estructura",
				Motivo: "no se pudo leer el directorio central"}
		}
		if !bytes.Equal(sig, []byte{0x50, 0x4B, 0x01, 0x02}) {
			return Result{Estado: Corrupto, Metodo: "estructura",
				Motivo: "el directorio central no esta donde el EOCD indica"}
		}
	}

	return Result{Estado: Valido, Score: 1, Metodo: "estructura"}
}
