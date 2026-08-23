//go:build !windows

package output

import (
	"fmt"
	"os"
	"syscall"
)

// sameUnderlyingDevice indica si escribir dentro de destDir escribiría sobre el
// mismo almacenamiento del que se está leyendo srcPath.
//
// Hay que distinguir dos casos, y confundirlos es el motivo de que la versión
// anterior nunca detectara nada:
//
//   - srcPath es un nodo de dispositivo (/dev/sdb1). Su campo Dev es el del
//     sistema de archivos donde vive el nodo (devtmpfs), NO el del dispositivo
//     que representa. El campo correcto es Rdev, y hay que compararlo contra el
//     Dev del destino.
//
//   - srcPath es una imagen regular (backup.img). Aquí Dev vs Dev sí es lo
//     correcto, pero coincidir no es destructivo: la imagen ya es una copia. Solo
//     se informa como "mismo dispositivo" el caso realmente peligroso.
func sameUnderlyingDevice(srcPath, destDir string) (bool, error) {
	srcInfo, err := os.Stat(srcPath)
	if err != nil {
		return false, err
	}
	destInfo, err := os.Stat(destDir)
	if err != nil {
		return false, err
	}

	// Una imagen regular no corre peligro de ser sobrescrita por sus propios
	// resultados; el riesgo real es escribir sobre el dispositivo en crudo.
	if srcInfo.Mode()&os.ModeDevice == 0 {
		return false, nil
	}

	srcStat, ok := srcInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return false, fmt.Errorf("no se pudo leer la información de dispositivo de %q", srcPath)
	}
	destStat, ok := destInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return false, fmt.Errorf("no se pudo leer la información de dispositivo de %q", destDir)
	}

	return uint64(srcStat.Rdev) == uint64(destStat.Dev), nil
}
