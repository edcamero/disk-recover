//go:build windows

package blockdev

import (
	"os"
	"testing"
)

// TestIOCTLConstants verifica los codigos de control derivandolos de la macro
// CTL_CODE de Windows:
//
//	CTL_CODE(t, f, m, a) = (t << 16) | (a << 14) | (f << 2) | m
//
// Un digito mal copiado no da error de compilacion: DeviceIoControl devuelve
// "Incorrect function" y la herramienta cae al fallback sin decir por que.
func TestIOCTLConstants(t *testing.T) {
	const (
		fileDeviceDisk = 0x00000007
		methodBuffered = 0
		fileAnyAccess  = 0
		fileReadAccess = 1
	)
	ctlCode := func(devType, function, method, access uint32) uint32 {
		return (devType << 16) | (access << 14) | (function << 2) | method
	}

	tests := []struct {
		name string
		got  uint32
		want uint32
	}{
		{
			"IOCTL_DISK_GET_LENGTH_INFO",
			ioctlDiskGetLengthInfo,
			ctlCode(fileDeviceDisk, 0x0017, methodBuffered, fileReadAccess),
		},
		{
			"IOCTL_DISK_GET_DRIVE_GEOMETRY",
			ioctlDiskGetGeometry,
			ctlCode(fileDeviceDisk, 0x0000, methodBuffered, fileAnyAccess),
		},
	}

	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s = %#08x, se esperaba %#08x", tt.name, tt.got, tt.want)
		}
	}
}

// TestDeviceSizeRealVolume consulta un volumen de verdad.
//
// Requiere Administrador, asi que se salta si no lo hay. Cuando SI se ejecuta
// elevado, es la unica prueba que valida de extremo a extremo que el IOCTL
// devuelve un tamano creible, que es justo lo que no se puede comprobar con un
// simulador.
func TestDeviceSizeRealVolume(t *testing.T) {
	const path = `\\.\C:`

	f, err := os.Open(path)
	if err != nil {
		t.Skipf("no se pudo abrir %s (se necesita Administrador): %v", path, err)
	}
	defer f.Close()

	size, err := DeviceSize(f)
	if err != nil {
		t.Fatalf("DeviceSize(%s): %v", path, err)
	}

	// Un volumen del sistema tiene al menos unos cuantos GB y menos de 1 PB.
	const minSize = 1 << 30
	const maxSize = 1 << 50
	if size < minSize || size > maxSize {
		t.Errorf("DeviceSize(%s) = %d bytes, valor poco creible", path, size)
	}
	t.Logf("%s: %d bytes (%.2f GB)", path, size, float64(size)/(1<<30))

	sector := DetectSectorSize(f)
	switch sector {
	case 512, 1024, 2048, 4096:
		t.Logf("sector detectado: %d bytes", sector)
	default:
		t.Errorf("DetectSectorSize = %d, no es un tamano valido", sector)
	}

	// El tamano de un dispositivo debe ser multiplo del sector; si no, el
	// recorte al final en AlignedReaderAt no seria correcto.
	if size%sector != 0 {
		t.Errorf("el tamano %d no es multiplo del sector %d", size, sector)
	}
}
