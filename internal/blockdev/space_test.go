package blockdev

import (
	"os"
	"testing"
)

func TestFreeSpace(t *testing.T) {
	dir := t.TempDir()

	libre, err := FreeSpace(dir)
	if err != nil {
		t.Fatalf("FreeSpace(%q): %v", dir, err)
	}
	if libre <= 0 {
		t.Errorf("FreeSpace = %d; el directorio temporal deberia tener espacio", libre)
	}
	t.Logf("espacio libre en %s: %.2f GB", dir, float64(libre)/(1<<30))
}

func TestFreeSpaceRutaInexistente(t *testing.T) {
	if _, err := FreeSpace("/ruta/que/no/existe/en/ningun/sistema"); err == nil {
		t.Error("se esperaba error con una ruta inexistente")
	}
}

// TestFreeSpaceEsCreible protege contra un error de unidades: devolver
// bloques en vez de bytes daria una cifra 512 o 4096 veces menor y la
// comprobacion de espacio dejaria pasar escaneos que no caben.
func TestFreeSpaceEsCreible(t *testing.T) {
	dir := os.TempDir()
	libre, err := FreeSpace(dir)
	if err != nil {
		t.Skipf("no se pudo consultar %s: %v", dir, err)
	}

	const minCreible = 1 << 20 // 1 MB
	const maxCreible = 1 << 50 // 1 PB
	if libre < minCreible || libre > maxCreible {
		t.Errorf("FreeSpace = %d bytes, cifra poco creible: revisa las unidades", libre)
	}
}
