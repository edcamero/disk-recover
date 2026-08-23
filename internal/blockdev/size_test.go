package blockdev

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDeviceSizeRegularFile: una imagen .img se resuelve por Stat, sin IOCTL.
func TestDeviceSizeRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "imagen.img")
	want := int64(12345)
	if err := os.WriteFile(path, make([]byte, want), 0o644); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	got, err := DeviceSize(f)
	if err != nil {
		t.Fatalf("DeviceSize: %v", err)
	}
	if got != want {
		t.Errorf("DeviceSize() = %d, se esperaba %d", got, want)
	}
}

// TestDeviceSizeEmptyFile: un archivo vacio no tiene tamano utilizable, y el
// error debe decirlo en vez de propagar un cero silencioso.
func TestDeviceSizeEmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vacio.img")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if _, err := DeviceSize(f); err == nil {
		t.Error("se esperaba error con un archivo vacio")
	}
}

// TestDeviceSizeDoesNotDisturbOffset: DeviceSize puede usar Seek internamente,
// pero no debe dejar el descriptor movido. Todo el resto del programa usa
// ReadAt, que ignora el offset, pero dejarlo desplazado es una trampa latente.
func TestDeviceSizeLeavesOffsetAtStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "imagen.img")
	if err := os.WriteFile(path, make([]byte, 4096), 0o644); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if _, err := DeviceSize(f); err != nil {
		t.Fatal(err)
	}

	pos, err := f.Seek(0, 1) // posicion actual
	if err != nil {
		t.Fatal(err)
	}
	if pos != 0 {
		t.Errorf("el descriptor quedo en la posicion %d, se esperaba 0", pos)
	}
}

// TestDetectSectorSizeFallback: sobre un archivo normal no hay geometria que
// consultar, asi que debe caer al valor por defecto sin fallar.
func TestDetectSectorSizeFallback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "imagen.img")
	if err := os.WriteFile(path, make([]byte, 1024), 0o644); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	got := DetectSectorSize(f)
	switch got {
	case 512, 1024, 2048, 4096:
	default:
		t.Errorf("DetectSectorSize() = %d, que no es un tamano de sector valido", got)
	}
}
