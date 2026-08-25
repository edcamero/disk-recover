//go:build !windows

package blockdev

import (
	"fmt"
	"syscall"
)

// FreeSpace devuelve los bytes libres en el sistema de archivos que contiene
// path.
//
// Sin esto, un escaneo largo que llena el destino falla archivo a archivo y
// termina con estadisticas enganosas. Comprobarlo antes convierte un fallo
// confuso en un mensaje accionable.
func FreeSpace(path string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, fmt.Errorf("no se pudo consultar el espacio en %q: %w", path, err)
	}
	// Bavail y no Bfree: los bloques reservados para root no estan disponibles
	// para un proceso normal, y contarlos daria una cifra optimista.
	return int64(st.Bavail) * int64(st.Bsize), nil
}
