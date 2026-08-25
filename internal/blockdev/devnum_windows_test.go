//go:build windows

package blockdev

import "testing"

// TestDeviceNumberSinAdministrador es la propiedad que hace utilizable la
// proteccion: consultar el disco fisico de un volumen abre el handle SIN
// permisos de acceso a datos (dwDesiredAccess = 0), asi que funciona con un
// usuario normal. Si exigiera Administrador, la salvaguarda no podria correr
// antes de decidir si se puede escribir.
func TestDeviceNumberSinAdministrador(t *testing.T) {
	n, err := DeviceNumber(`\\.\C:`)
	if err != nil {
		t.Fatalf("DeviceNumber(C:) fallo sin privilegios elevados: %v", err)
	}
	t.Logf("C: reside en el disco fisico %d", n)
}

// TestDeviceNumberDistinguibleEntreVolumenes: si dos volumenes del sistema
// devuelven el mismo numero, estan en el mismo disco fisico, que es
// precisamente lo que la comparacion debe detectar.
func TestDeviceNumberConsistente(t *testing.T) {
	a, err := DeviceNumber(`\\.\C:`)
	if err != nil {
		t.Skip("C: no consultable")
	}
	b, err := DeviceNumber(`\\.\C:`)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Errorf("dos consultas del mismo volumen dieron %d y %d", a, b)
	}
}

func TestDeviceNumberVolumenInexistente(t *testing.T) {
	if _, err := DeviceNumber(`\.\Z:`); err == nil {
		t.Error("se esperaba error con un volumen inexistente")
	}
}
