// Package blockdev adapta el acceso a dispositivos en crudo, que imponen
// restricciones que un archivo normal no tiene.
package blockdev

import (
	"io"
	"runtime"
	"strings"
)

// DefaultSectorSize es el tamaño de sector asumido cuando no se indica otro.
// 512 sigue siendo el denominador común: los discos "Advanced Format" de 4K
// exponen emulación de 512 salvo en modo 4Kn.
const DefaultSectorSize = 512

// AlignedReaderAt envuelve un io.ReaderAt que solo acepta lecturas alineadas a
// sector, y le da una interfaz que acepta cualquier offset y longitud.
//
// Por qué hace falta: en Windows, CreateFile sobre \\.\PhysicalDriveN o \\.\C:
// abre el dispositivo en modo sin búfer, y ahí TANTO el offset COMO la longitud
// de cada lectura deben ser múltiplos del tamaño de sector. Cualquier otra
// lectura falla con ERROR_INVALID_PARAMETER.
//
// El carver incumple eso de forma natural: al extraer un archivo lee exactamente
// sus bytes, y el tamaño de un JPEG no tiene por qué ser múltiplo de 512. La
// última lectura de cada archivo queda desalineada y falla, de modo que sobre un
// disco en crudo no se recuperaría absolutamente nada.
//
// Linux es más permisivo con /dev/sdX abierto sin O_DIRECT, pero alinear
// tampoco le hace daño.
type AlignedReaderAt struct {
	src    io.ReaderAt
	sector int64
	size   int64
}

// NewAligned envuelve src. Un sector <= 0 usa DefaultSectorSize; size es el
// tamaño del dispositivo y acota las lecturas para no pedir más allá del final.
func NewAligned(src io.ReaderAt, sector, size int64) *AlignedReaderAt {
	if sector <= 0 {
		sector = DefaultSectorSize
	}
	return &AlignedReaderAt{src: src, sector: sector, size: size}
}

// ReadAt cumple io.ReaderAt sin exigir alineación al llamante.
func (a *AlignedReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if off < 0 {
		return 0, io.EOF
	}

	// Ruta rápida: si ya está alineado no hay nada que hacer y no se copia nada.
	if off%a.sector == 0 && int64(len(p))%a.sector == 0 {
		return a.src.ReadAt(p, off)
	}

	// Calcular el rango alineado que contiene [off, off+len(p)).
	start := off - off%a.sector
	end := off + int64(len(p))
	if rem := end % a.sector; rem != 0 {
		end += a.sector - rem
	}
	if a.size > 0 && end > a.size {
		// El final del dispositivo debería ser múltiplo de sector; si no lo es,
		// se recorta y se acepta la última lectura corta.
		end = a.size
	}
	if end <= start {
		return 0, io.EOF
	}

	buf := make([]byte, end-start)
	n, err := a.src.ReadAt(buf, start)

	// Recortar a la ventana que pidió el llamante.
	skip := off - start
	if int64(n) <= skip {
		if err == nil {
			err = io.EOF
		}
		return 0, err
	}

	copied := copy(p, buf[skip:n])
	if copied < len(p) && err == nil {
		err = io.EOF
	}
	return copied, err
}

// SectorSize devuelve el tamaño de sector en uso.
func (a *AlignedReaderAt) SectorSize() int64 { return a.sector }

// IsRawDevice indica si una ruta apunta a un dispositivo en crudo y no a un
// archivo de imagen normal.
//
//	Windows: \\.\PhysicalDrive0, \\.\C:
//	Unix:    /dev/sdb1, /dev/disk2
func IsRawDevice(path string) bool {
	if runtime.GOOS == "windows" {
		return strings.HasPrefix(path, `\\.\`) || strings.HasPrefix(path, "//./")
	}
	return strings.HasPrefix(path, "/dev/")
}
