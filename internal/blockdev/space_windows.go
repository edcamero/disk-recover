//go:build windows

package blockdev

import (
	"fmt"
	"syscall"
	"unsafe"
)

// FreeSpace devuelve los bytes libres en el volumen que contiene path.
//
// Sin esto, un escaneo de 2 TB que llena el destino a las cuatro horas falla
// archivo a archivo y termina con estadisticas enganosas. Comprobarlo antes de
// empezar convierte un fallo confuso en un mensaje accionable.
func FreeSpace(path string) (int64, error) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	proc := kernel32.NewProc("GetDiskFreeSpaceExW")

	ptr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, fmt.Errorf("ruta invalida %q: %w", path, err)
	}

	var libresParaUsuario, totales, libresTotales uint64
	r, _, callErr := proc.Call(
		uintptr(unsafe.Pointer(ptr)),
		uintptr(unsafe.Pointer(&libresParaUsuario)),
		uintptr(unsafe.Pointer(&totales)),
		uintptr(unsafe.Pointer(&libresTotales)),
	)
	if r == 0 {
		return 0, fmt.Errorf("no se pudo consultar el espacio en %q: %w", path, callErr)
	}

	// Se devuelve el espacio disponible PARA EL USUARIO ACTUAL, no el libre
	// total del volumen: con cuotas activas son distintos, y el que limita de
	// verdad es el primero.
	return int64(libresParaUsuario), nil
}

// DeviceNumber devuelve el numero de disco fisico que respalda a path.
//
// Es lo que permite cerrar el hueco del guard de origen: comparando el disco
// fisico del destino con el del origen se detecta que ambos estan en el mismo
// dispositivo aunque el origen sea \\.\PhysicalDriveN, que no tiene letra de
// unidad asociable por comparacion de cadenas.
func DeviceNumber(path string) (uint32, error) {
	// El volumen se abre sin permisos de acceso a datos: basta con el handle
	// para consultar propiedades, y asi no hace falta ser Administrador.
	ptr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}

	h, err := syscall.CreateFile(
		ptr,
		0, // sin GENERIC_READ: solo consulta de metadatos
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil,
		syscall.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return 0, err
	}
	defer syscall.CloseHandle(h)

	// STORAGE_DEVICE_NUMBER: DeviceType(4) DeviceNumber(4) PartitionNumber(4)
	var out [12]byte
	var devueltos uint32

	const ioctlStorageGetDeviceNumber = 0x002D1080

	if err := syscall.DeviceIoControl(
		h, ioctlStorageGetDeviceNumber,
		nil, 0,
		&out[0], uint32(len(out)),
		&devueltos, nil,
	); err != nil {
		return 0, err
	}
	if devueltos < 8 {
		return 0, fmt.Errorf("respuesta demasiado corta: %d bytes", devueltos)
	}

	return uint32(out[4]) | uint32(out[5])<<8 | uint32(out[6])<<16 | uint32(out[7])<<24, nil
}
