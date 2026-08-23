//go:build windows

package blockdev

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"syscall"
)

// Códigos de control para consultar un dispositivo de disco.
//
//	IOCTL_DISK_GET_LENGTH_INFO    devuelve el tamaño en bytes
//	IOCTL_DISK_GET_DRIVE_GEOMETRY devuelve la geometría, con BytesPerSector
const (
	ioctlDiskGetLengthInfo = 0x0007405C
	ioctlDiskGetGeometry   = 0x00070000
)

// DeviceSize devuelve el tamaño en bytes de un archivo o dispositivo.
//
// En Windows, un manejador de volumen en crudo (\\.\D:) o de disco físico
// (\\.\PhysicalDrive0) NO admite SetFilePointerEx hasta el final: Seek falla con
// "The parameter is incorrect". Hay que preguntarle al dispositivo con
// DeviceIoControl.
//
// Orden: archivo regular por Stat, luego IOCTL, luego Seek como último recurso.
func DeviceSize(f *os.File) (int64, error) {
	// Archivo regular (una imagen .img): Stat basta y es lo más barato.
	if info, err := f.Stat(); err == nil && info.Mode().IsRegular() && info.Size() > 0 {
		return info.Size(), nil
	}

	if size, err := ioctlLength(f); err == nil && size > 0 {
		return size, nil
	}

	// Último recurso: puede funcionar en algunos dispositivos virtuales.
	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return 0, fmt.Errorf(
			"no se pudo determinar el tamaño de %s.\n"+
				"   El dispositivo no respondió a IOCTL_DISK_GET_LENGTH_INFO ni admite Seek.\n"+
				"   Comprueba que la ruta es de la forma \\\\.\\D: o \\\\.\\PhysicalDrive1",
			f.Name())
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return 0, fmt.Errorf("no se pudo rebobinar %s: %w", f.Name(), err)
	}
	if size <= 0 {
		return 0, fmt.Errorf("%s reportó tamaño %d", f.Name(), size)
	}
	return size, nil
}

// ioctlLength pregunta el tamaño con IOCTL_DISK_GET_LENGTH_INFO.
// La respuesta es un GET_LENGTH_INFORMATION: un único LARGE_INTEGER.
func ioctlLength(f *os.File) (int64, error) {
	var out [8]byte
	var returned uint32

	err := syscall.DeviceIoControl(
		syscall.Handle(f.Fd()),
		ioctlDiskGetLengthInfo,
		nil, 0,
		&out[0], uint32(len(out)),
		&returned, nil,
	)
	if err != nil {
		return 0, err
	}
	if returned < 8 {
		return 0, fmt.Errorf("respuesta demasiado corta: %d bytes", returned)
	}

	return int64(binary.LittleEndian.Uint64(out[:])), nil
}

// DetectSectorSize consulta el tamaño de sector real del dispositivo.
//
// Evita que el usuario tenga que adivinar entre 512 y 4096: un disco 4Kn
// nativo rechaza cualquier lectura alineada a 512. Si no se puede averiguar,
// devuelve DefaultSectorSize.
func DetectSectorSize(f *os.File) int64 {
	// DISK_GEOMETRY: Cylinders(8) MediaType(4) TracksPerCylinder(4)
	//                SectorsPerTrack(4) BytesPerSector(4) = 24 bytes
	var out [24]byte
	var returned uint32

	err := syscall.DeviceIoControl(
		syscall.Handle(f.Fd()),
		ioctlDiskGetGeometry,
		nil, 0,
		&out[0], uint32(len(out)),
		&returned, nil,
	)
	if err != nil || returned < 24 {
		return DefaultSectorSize
	}

	sector := int64(binary.LittleEndian.Uint32(out[20:24]))
	switch sector {
	case 512, 1024, 2048, 4096:
		return sector
	}
	return DefaultSectorSize
}
