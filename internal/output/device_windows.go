//go:build windows

package output

import (
	"path/filepath"
	"strings"
)

// sameUnderlyingDevice indica si escribir dentro de destDir escribiría sobre el
// mismo almacenamiento del que se está leyendo srcPath.
//
// En Windows no existen nodos de dispositivo con Rdev. El acceso a un disco en
// crudo se hace con rutas de espacio de nombres: \\.\PhysicalDrive0 o \\.\C:.
// Solo esas son peligrosas; una imagen regular en el mismo volumen que la salida
// no corre riesgo de ser sobrescrita por sus propios resultados.
//
// Limitación conocida: \\.\PhysicalDriveN no se puede asociar a una letra de
// unidad sin consultar los volúmenes del sistema, así que ese caso se trata como
// no coincidente. Cubre \\.\X: que es la forma que sí se puede comparar.
func sameUnderlyingDevice(srcPath, destDir string) (bool, error) {
	const devicePrefix = `\\.\`

	if !strings.HasPrefix(srcPath, devicePrefix) {
		return false, nil
	}

	destAbs, err := filepath.Abs(destDir)
	if err != nil {
		return false, err
	}

	// \\.\C:  ->  "C:"   (VolumeName devuelve la letra sin barra final)
	srcVolume := strings.TrimSuffix(strings.TrimPrefix(srcPath, devicePrefix), `\`)
	if !strings.HasSuffix(srcVolume, ":") {
		// \\.\PhysicalDrive0 y similares: no comparable de forma fiable.
		return false, nil
	}

	return strings.EqualFold(srcVolume, filepath.VolumeName(destAbs)), nil
}
