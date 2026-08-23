//go:build !windows

package blockdev

import (
	"fmt"
	"io"
	"os"
)

// DeviceSize devuelve el tamaño en bytes de un archivo o dispositivo.
//
// En Linux y macOS, Stat().Size() devuelve 0 para un dispositivo de bloque:
// st_size solo tiene sentido en archivos regulares. Buscar el final del
// dispositivo con Seek sí funciona, a diferencia de Windows.
func DeviceSize(f *os.File) (int64, error) {
	if info, err := f.Stat(); err == nil && info.Size() > 0 {
		return info.Size(), nil
	}

	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return 0, fmt.Errorf("no se pudo determinar el tamaño de %s: %w", f.Name(), err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return 0, fmt.Errorf("no se pudo rebobinar %s: %w", f.Name(), err)
	}
	if size <= 0 {
		return 0, fmt.Errorf("%s no tiene tamaño legible", f.Name())
	}
	return size, nil
}

// DetectSectorSize no está implementado fuera de Windows: aquí las lecturas
// desalineadas solo fallan con O_DIRECT, que no usamos.
func DetectSectorSize(f *os.File) int64 {
	return DefaultSectorSize
}
