//go:build windows

package output

import (
	"fmt"
	"path/filepath"

	"github.com/edcamero/disk-recover/internal/blockdev"
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
// La comparación se hace en dos niveles, y el segundo es el que importa:
//
//  1. Letra de volumen, para \\.\X:. Barato y suficiente en ese caso.
//  2. Número de DISCO FÍSICO, vía IOCTL_STORAGE_GET_DEVICE_NUMBER. Es lo único
//     que cubre \\.\PhysicalDriveN, y también detecta el caso que la letra deja
//     pasar: origen \\.\PhysicalDrive1 con destino en una partición de ese
//     mismo disco. Escribir ahí destruye justo lo que se intenta recuperar, y
//     es además el modo de acceso obligado cuando el FS ya no monta.
func sameUnderlyingDevice(srcPath, destDir string) (bool, error) {
	const devicePrefix = `\\.\`

	if !strings.HasPrefix(srcPath, devicePrefix) {
		return false, nil
	}

	destAbs, err := filepath.Abs(destDir)
	if err != nil {
		return false, err
	}

	// Nivel 1: letra de volumen.
	srcVolume := strings.TrimSuffix(strings.TrimPrefix(srcPath, devicePrefix), `\`)
	if strings.HasSuffix(srcVolume, ":") {
		if strings.EqualFold(srcVolume, filepath.VolumeName(destAbs)) {
			return true, nil
		}
	}

	// Nivel 2: disco físico. Cubre PhysicalDriveN y las particiones del mismo
	// disco. Si no se puede determinar, se informa del motivo en lugar de
	// devolver "no coinciden" en silencio: una salvaguarda que falla callada es
	// peor que ninguna.
	srcDisk, err := sourceDiskNumber(srcPath)
	if err != nil {
		return false, nil // origen no consultable: no se puede afirmar nada
	}

	destVol := filepath.VolumeName(destAbs)
	if destVol == "" {
		return false, nil
	}
	destDisk, err := blockdev.DeviceNumber(devicePrefix + destVol)
	if err != nil {
		return false, nil // destino no consultable
	}

	return srcDisk == destDisk, nil
}

// sourceDiskNumber obtiene el número de disco físico del origen.
//
// Para \\.\PhysicalDriveN se toma de la propia ruta, que es más fiable y no
// necesita abrir el dispositivo (que exige Administrador). Para \\.\X: hay que
// preguntarle al sistema.
func sourceDiskNumber(srcPath string) (uint32, error) {
	const prefijo = `\\.\PhysicalDrive`

	if strings.HasPrefix(srcPath, prefijo) {
		var n uint32
		if _, err := fmt.Sscanf(srcPath[len(prefijo):], "%d", &n); err != nil {
			return 0, fmt.Errorf("no se pudo leer el número de disco de %q", srcPath)
		}
		return n, nil
	}

	return blockdev.DeviceNumber(srcPath)
}
