package blockdev

import (
	"fmt"
	"io"
	"runtime"
	"testing"
)

// strictDevice imita un dispositivo en crudo de Windows: rechaza cualquier
// lectura cuyo offset o longitud no sean múltiplos del tamaño de sector.
type strictDevice struct {
	data    []byte
	sector  int64
	rejects int
}

func (d *strictDevice) ReadAt(p []byte, off int64) (int, error) {
	if off%d.sector != 0 || int64(len(p))%d.sector != 0 {
		d.rejects++
		return 0, fmt.Errorf("ERROR_INVALID_PARAMETER: off=%d len=%d", off, len(p))
	}
	if off >= int64(len(d.data)) {
		return 0, io.EOF
	}
	n := copy(p, d.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func testData(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}

// TestAlignedReadsArbitraryRanges es el caso que motiva todo el paquete: el
// carver pide exactamente los bytes de un archivo, y un JPEG no mide un
// múltiplo de 512.
func TestAlignedReadsArbitraryRanges(t *testing.T) {
	const size = 64 << 10
	data := testData(size)
	dev := &strictDevice{data: data, sector: 512}
	a := NewAligned(dev, 512, size)

	// Offsets y longitudes deliberadamente feos.
	cases := []struct{ off, length int64 }{
		{0, 1}, {1, 1}, {3, 137}, {511, 2}, {512, 1},
		{1000, 45193 % 4096}, {4096, 137}, {5000, 3000},
		{size - 1, 1}, {size - 700, 700},
	}

	for _, c := range cases {
		p := make([]byte, c.length)
		n, err := a.ReadAt(p, c.off)
		if err != nil && err != io.EOF {
			t.Errorf("ReadAt(len=%d, off=%d) error: %v", c.length, c.off, err)
			continue
		}
		if int64(n) != c.length {
			t.Errorf("ReadAt(len=%d, off=%d) devolvió %d bytes", c.length, c.off, n)
			continue
		}
		want := data[c.off : c.off+c.length]
		for i := range want {
			if p[i] != want[i] {
				t.Errorf("ReadAt(len=%d, off=%d): byte %d = %d, se esperaba %d",
					c.length, c.off, i, p[i], want[i])
				break
			}
		}
	}

	if dev.rejects != 0 {
		t.Errorf("el dispositivo rechazó %d lecturas: el envoltorio no alineó bien", dev.rejects)
	}
}

// TestAlignedFastPath: una lectura ya alineada debe pasar tal cual, sin copia
// intermedia. Es el 99% de las lecturas del scanner.
func TestAlignedFastPath(t *testing.T) {
	data := testData(8192)
	dev := &strictDevice{data: data, sector: 512}
	a := NewAligned(dev, 512, 8192)

	p := make([]byte, 1024)
	n, err := a.ReadAt(p, 2048)
	if err != nil || n != 1024 {
		t.Fatalf("ReadAt alineado: n=%d err=%v", n, err)
	}
	for i := range p {
		if p[i] != data[2048+i] {
			t.Fatalf("byte %d incorrecto", i)
		}
	}
}

func TestAlignedNearEndOfDevice(t *testing.T) {
	const size = 4096
	data := testData(size)
	dev := &strictDevice{data: data, sector: 512}
	a := NewAligned(dev, 512, size)

	// Leer los últimos bytes, donde redondear hacia arriba se saldría del final.
	p := make([]byte, 100)
	n, err := a.ReadAt(p, size-100)
	if err != nil && err != io.EOF {
		t.Fatalf("ReadAt al final: %v", err)
	}
	if n != 100 {
		t.Errorf("n = %d, se esperaba 100", n)
	}
	if dev.rejects != 0 {
		t.Errorf("%d lecturas rechazadas cerca del final", dev.rejects)
	}
}

func TestAlignedPastEnd(t *testing.T) {
	dev := &strictDevice{data: testData(2048), sector: 512}
	a := NewAligned(dev, 512, 2048)

	p := make([]byte, 100)
	if _, err := a.ReadAt(p, 5000); err == nil {
		t.Error("se esperaba error al leer más allá del final")
	}
}

func TestAlignedDefaultsSector(t *testing.T) {
	a := NewAligned(&strictDevice{data: testData(1024), sector: 512}, 0, 1024)
	if a.SectorSize() != DefaultSectorSize {
		t.Errorf("SectorSize() = %d, se esperaba %d", a.SectorSize(), DefaultSectorSize)
	}
}

func TestAligned4KSector(t *testing.T) {
	const size = 64 << 10
	data := testData(size)
	dev := &strictDevice{data: data, sector: 4096}
	a := NewAligned(dev, 4096, size)

	p := make([]byte, 137)
	n, err := a.ReadAt(p, 5000)
	if err != nil && err != io.EOF {
		t.Fatalf("ReadAt con sector 4K: %v", err)
	}
	if n != 137 {
		t.Errorf("n = %d, se esperaba 137", n)
	}
	if dev.rejects != 0 {
		t.Errorf("%d lecturas rechazadas con sector de 4K", dev.rejects)
	}
	for i := 0; i < n; i++ {
		if p[i] != data[5000+i] {
			t.Fatalf("byte %d incorrecto", i)
		}
	}
}

func TestIsRawDevice(t *testing.T) {
	// El resultado depende de la plataforma; se comprueba la que corresponda.
	windows := []string{`\\.\PhysicalDrive0`, `\\.\C:`}
	unix := []string{"/dev/sdb1", "/dev/disk2"}
	neither := []string{"backup.img", "C:\\Users\\yo\\backup.img", "./imagen.dd", ""}

	for _, p := range neither {
		if IsRawDevice(p) {
			t.Errorf("IsRawDevice(%q) = true, se esperaba false", p)
		}
	}
	// Solo una de las dos familias aplica en cada plataforma; comprobamos que
	// al menos la propia se reconozca.
	anyRecognised := false
	for _, p := range append(append([]string{}, windows...), unix...) {
		if IsRawDevice(p) {
			anyRecognised = true
		}
	}
	if !anyRecognised {
		t.Error("no se reconoció ninguna ruta de dispositivo en crudo")
	}
}

func FuzzAlignedReadAt(f *testing.F) {
	f.Add(int64(0), 512)
	f.Add(int64(137), 3)
	f.Add(int64(-5), 100)

	const size = 8192
	data := testData(size)

	f.Fuzz(func(t *testing.T, off int64, length int) {
		if length < 0 || length > size*2 {
			return
		}
		dev := &strictDevice{data: data, sector: 512}
		a := NewAligned(dev, 512, size)

		p := make([]byte, length)
		n, _ := a.ReadAt(p, off) // no debe hacer panic

		if n > length {
			t.Fatalf("devolvió %d bytes para un buffer de %d", n, length)
		}
		// Lo que devuelva tiene que coincidir con el origen.
		for i := 0; i < n; i++ {
			if off+int64(i) < int64(len(data)) && p[i] != data[off+int64(i)] {
				t.Fatalf("byte %d en off=%d: %d != %d", i, off, p[i], data[off+int64(i)])
			}
		}
		if dev.rejects != 0 {
			t.Fatalf("lectura no alineada con off=%d len=%d", off, length)
		}
	})
}

// TestNormalizeSource cubre el error real que reporto un usuario: pasar "D:"
// como origen. En Windows eso abre la CARPETA actual de la unidad D, no sus
// bytes: Stat devuelve Size=0 y ReadAt falla con "Incorrect function", lo que
// producia el mensaje inutil "D: no tiene tamano legible".
func TestNormalizeSource(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("la normalizacion de letra de unidad solo aplica en Windows")
	}

	shouldChange := map[string]string{
		`D:`:  `\\.\D:`,
		`D:\`: `\\.\D:`,
		`d:`:  `\\.\D:`,
		`d:/`: `\\.\D:`,
		`E:\`: `\\.\E:`,
	}
	for in, want := range shouldChange {
		got, changed := NormalizeSource(in)
		if !changed {
			t.Errorf("NormalizeSource(%q): no se normalizo", in)
			continue
		}
		if got != want {
			t.Errorf("NormalizeSource(%q) = %q, se esperaba %q", in, got, want)
		}
		if !IsRawDevice(got) {
			t.Errorf("NormalizeSource(%q) = %q, que no se reconoce como dispositivo", in, got)
		}
	}

	// Rutas que NO deben tocarse: son archivos o ya son rutas en crudo.
	shouldNotChange := []string{
		`D:\backup.img`,
		`backup.img`,
		`.\imagen.dd`,
		`\\.\PhysicalDrive0`,
		`\\.\D:`,
		`C:\Users\yo\disco.img`,
		``,
	}
	for _, in := range shouldNotChange {
		if got, changed := NormalizeSource(in); changed {
			t.Errorf("NormalizeSource(%q) = %q: no debia cambiar", in, got)
		}
	}
}
