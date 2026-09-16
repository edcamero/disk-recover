package namerecovery

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestMemoriaNoEscalaConElArchivo comprueba la propiedad que hace usable la
// recuperacion de nombres: procesar un video de 2 GB no debe costar 2 GB de RAM.
//
// El riesgo es real y facil de introducir: basta un os.ReadFile para buscar el
// paquete XMP. Con miles de archivos recuperados, cada uno cargado entero,
// el proceso muere o hace swap hasta congelar la maquina.
func TestMemoriaNoEscalaConElArchivo(t *testing.T) {
	if testing.Short() {
		t.Skip("omitido en modo -short")
	}

	dir := t.TempDir()
	tamanos := []int{1 << 20, 16 << 20, 128 << 20} // 1 MB, 16 MB, 128 MB
	var picos []uint64

	for _, size := range tamanos {
		path := filepath.Join(dir, "grande.bin")

		// Un archivo con cabecera JPEG y relleno: representa un video o un RAW
		// grande del que hay que sacar el nombre.
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		f.Write([]byte{0xFF, 0xD8, 0xFF, 0xE0})
		bloque := bytes.Repeat([]byte{0x41}, 1<<20)
		for escrito := 4; escrito < size; escrito += len(bloque) {
			f.Write(bloque)
		}
		f.Close()

		runtime.GC()
		var antes runtime.MemStats
		runtime.ReadMemStats(&antes)

		r := NewResolver(bytes.NewReader(make([]byte, 1<<20)))
		if _, err := r.Resolve(path, 0, int64(size)); err != nil {
			t.Fatalf("Resolve con %d MB: %v", size>>20, err)
		}

		var despues runtime.MemStats
		runtime.ReadMemStats(&despues)

		asignado := despues.TotalAlloc - antes.TotalAlloc
		picos = append(picos, asignado)
		t.Logf("archivo de %4d MB -> asignados %.2f MB", size>>20, float64(asignado)/(1<<20))

		os.Remove(path)
		runtime.GC()
	}

	// Lo asignado no debe crecer con el tamano del archivo. Se compara el
	// primero con el ultimo: 128x mas archivo no debe dar 128x mas memoria.
	primero, ultimo := picos[0], picos[len(picos)-1]
	if ultimo > primero*3 {
		t.Errorf("asignados %.2f MB para 1 MB y %.2f MB para 128 MB: "+
			"el consumo depende del tamano del archivo",
			float64(primero)/(1<<20), float64(ultimo)/(1<<20))
	}
}

// TestMetadatosAlFinalSeEncuentran cubre los formatos que ponen sus metadatos
// al FINAL del archivo.
//
// readHeader solo mira los primeros 256 KB. Varios formatos ponen sus metadatos
// al FINAL del archivo:
//
//	MP4/MOV  el atomo 'moov' va al final cuando la camara graba en streaming
//	XMP      Adobe lo escribe al final en algunos flujos de exportacion
//	ID3v1    los ultimos 128 bytes de un MP3
//
// Antes solo se miraban los primeros 256 KB, asi que el nombre de un video de
// camara no se recuperaba nunca aunque estuviera escrito dentro del archivo.
// La solucion NO es leer el archivo entero —eso es justo el OOM que hay que
// evitar— sino leer tambien una ventana acotada del final.
func TestMetadatosAlFinalSeEncuentran(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "video.jpg")

	xmp := `<x:xmpmeta><rdf:Description xmpMM:PreservedFileName="MiVideo.jpg">` +
		`</rdf:Description></x:xmpmeta>`

	// Un archivo de 1 MB con el XMP en los ultimos bytes.
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte{0xFF, 0xD8, 0xFF, 0xE0})
	f.Write(bytes.Repeat([]byte{0x41}, 1<<20))
	f.Write([]byte(xmp))
	f.Close()

	r := NewResolver(bytes.NewReader(make([]byte, 1<<20)))
	nombre, err := r.Resolve(path, 0, 1<<20)
	if err != nil {
		t.Fatal(err)
	}

	if nombre != "MiVideo.jpg" {
		t.Errorf("no se recuperaron los metadatos del FINAL: se obtuvo %q", nombre)
	}
}

// TestArchivoPequenoNoDuplicaLectura: si el archivo cabe entero en la cabecera,
// leer ademas la cola procesaria dos veces los mismos bytes.
func TestArchivoPequenoNoDuplicaLectura(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pequeno.jpg")
	contenido := append([]byte{0xFF, 0xD8, 0xFF, 0xE0}, bytes.Repeat([]byte{0x41}, 1000)...)
	if err := os.WriteFile(path, contenido, 0o644); err != nil {
		t.Fatal(err)
	}

	cabecera, cola, err := leerExtremos(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cabecera) != len(contenido) {
		t.Errorf("cabecera de %d bytes, el archivo mide %d", len(cabecera), len(contenido))
	}
	if len(cola) != 0 {
		t.Errorf("cola de %d bytes en un archivo que cabe entero en la cabecera", len(cola))
	}
}

// TestCabeceraYColaNoSeSolapan: en un archivo mediano, la ventana del final no
// debe repetir bytes que ya vienen en la cabecera.
func TestCabeceraYColaNoSeSolapan(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mediano.bin")

	// 300 KB: mayor que headerBytes (256 KB) pero menor que la suma de ambas
	// ventanas, que es justo donde se solaparían.
	const size = 300 << 10
	if err := os.WriteFile(path, bytes.Repeat([]byte{0x42}, size), 0o644); err != nil {
		t.Fatal(err)
	}

	cabecera, cola, err := leerExtremos(path)
	if err != nil {
		t.Fatal(err)
	}

	total := len(cabecera) + len(cola)
	if total > size {
		t.Errorf("cabecera (%d) + cola (%d) = %d bytes sobre un archivo de %d: se solapan",
			len(cabecera), len(cola), total, size)
	}
	if total != size {
		t.Errorf("cabecera + cola = %d, se esperaba cubrir los %d bytes", total, size)
	}
}
