package manifest

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func nuevoWriter(t *testing.T) (*Writer, string) {
	t.Helper()
	dir := t.TempDir()
	w, err := Create(dir, Header{
		Origen:      "/dev/sdb1",
		OrigenBytes: 1 << 30,
		Destino:     dir,
		Modo:        "carve",
		Herramienta: "disk-recover test",
	})
	if err != nil {
		t.Fatal(err)
	}
	return w, filepath.Join(dir, Nombre)
}

func entrada(offset, size int64, hash string) Entry {
	return Entry{
		Offset: offset, Size: size, Metodo: "carve",
		Formato: "jpeg", SHA256: hash,
		Integridad: 1, Validacion: "valido", ValidMetodo: "decodificacion",
		Categoria: "photo", EsUsuario: true, FooterHallado: true,
		Destino: "user_content/photo/foto.jpg",
	}
}

func TestEscrituraYLectura(t *testing.T) {
	w, path := nuevoWriter(t)

	for i := 0; i < 5; i++ {
		if err := w.Add(entrada(int64(i)*1000, 500, "hash")); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(true, nil); err != nil {
		t.Fatal(err)
	}

	res, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}

	if res.Header.Origen != "/dev/sdb1" {
		t.Errorf("Origen = %q", res.Header.Origen)
	}
	if len(res.Entradas) != 5 {
		t.Errorf("%d entradas, se esperaban 5", len(res.Entradas))
	}
	if res.Footer == nil {
		t.Fatal("sin footer")
	}
	if !res.Footer.Completado {
		t.Error("Completado = false tras un cierre normal")
	}
	if res.Footer.Archivos != 5 {
		t.Errorf("Archivos = %d, se esperaban 5", res.Footer.Archivos)
	}
	if res.Reanudable() {
		t.Error("un escaneo completado no deberia ser reanudable")
	}
}

// TestManifiestoTruncadoEsLegible es la propiedad que justifica JSONL frente a
// un unico documento JSON: un corte de energia deja el archivo a medias, y aun
// asi debe poder leerse hasta la ultima linea completa. Con un array JSON haria
// falta el cierre y el archivo quedaria irrecuperable.
func TestManifiestoTruncadoEsLegible(t *testing.T) {
	w, path := nuevoWriter(t)
	for i := 0; i < 10; i++ {
		if err := w.Add(entrada(int64(i)*1000, 500, "h")); err != nil {
			t.Fatal(err)
		}
	}
	// Abort en vez de Close: deja el manifiesto sin footer, como un corte de
	// energia, pero libera el descriptor.
	if err := w.Abort(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Cortar a mitad de la ultima linea.
	corte := len(data) - 40
	if corte < 0 {
		t.Fatal("manifiesto demasiado corto para la prueba")
	}
	if err := os.WriteFile(path, data[:corte], 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := Read(path)
	if err != nil {
		t.Fatalf("un manifiesto truncado deberia leerse: %v", err)
	}
	if len(res.Entradas) < 8 {
		t.Errorf("solo %d entradas recuperadas de 10; se pierde demasiado", len(res.Entradas))
	}
	if res.Footer != nil {
		t.Error("no deberia haber footer en un manifiesto interrumpido")
	}
	if !res.Reanudable() {
		t.Error("un escaneo interrumpido debe ser reanudable")
	}
	t.Logf("recuperadas %d de 10 entradas; ultimo offset %d",
		len(res.Entradas), res.UltimoOfset)
}

// TestPuntoDeReanudacion: el manifiesto debe decir por donde continuar.
func TestPuntoDeReanudacion(t *testing.T) {
	w, path := nuevoWriter(t)
	offsets := []int64{1000, 50000, 900000, 12000000}
	for _, off := range offsets {
		if err := w.Add(entrada(off, 4096, "h")); err != nil {
			t.Fatal(err)
		}
	}
	w.Close(false, nil)

	res, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}

	quiero := offsets[len(offsets)-1] + 4096
	if res.UltimoOfset != quiero {
		t.Errorf("UltimoOfset = %d, se esperaba %d", res.UltimoOfset, quiero)
	}
	if !res.Reanudable() {
		t.Error("Completado=false deberia dar Reanudable=true")
	}
}

func TestHashesParaDeduplicar(t *testing.T) {
	w, path := nuevoWriter(t)
	w.Add(entrada(0, 100, "aaa"))
	w.Add(entrada(200, 100, "bbb"))
	w.Add(entrada(400, 100, "aaa")) // duplicado
	w.Close(true, nil)

	res, _ := Read(path)
	hashes := res.Hashes()

	if len(hashes) != 2 {
		t.Errorf("%d hashes unicos, se esperaban 2", len(hashes))
	}
	if !hashes["aaa"] || !hashes["bbb"] {
		t.Error("faltan hashes en el conjunto")
	}
}

func TestContadoresDescartesYCorruptos(t *testing.T) {
	w, path := nuevoWriter(t)

	w.Add(entrada(0, 100, "a"))

	corrupto := entrada(200, 100, "b")
	corrupto.Validacion = "corrupto"
	corrupto.ValidMotivo = "CRC incorrecto"
	corrupto.Destino = "dudosos/foto.jpg"
	w.Add(corrupto)

	descartado := entrada(400, 100, "c")
	descartado.Destino = ""
	descartado.Descarte = "solo se conserva contenido de usuario"
	w.Add(descartado)

	w.Close(true, nil)

	res, _ := Read(path)
	if res.Footer.Archivos != 2 {
		t.Errorf("Archivos = %d, se esperaban 2", res.Footer.Archivos)
	}
	if res.Footer.Descartados != 1 {
		t.Errorf("Descartados = %d, se esperaba 1", res.Footer.Descartados)
	}
	if res.Footer.Corruptos != 1 {
		t.Errorf("Corruptos = %d, se esperaba 1", res.Footer.Corruptos)
	}
}

func TestRegionesIlegibles(t *testing.T) {
	w, path := nuevoWriter(t)
	w.Add(entrada(0, 100, "a"))
	w.Close(true, []RegionJSON{{Offset: 4096, Length: 512}, {Offset: 999424, Length: 2048}})

	res, _ := Read(path)
	if len(res.Footer.Ilegibles) != 2 {
		t.Fatalf("%d regiones, se esperaban 2", len(res.Footer.Ilegibles))
	}
	if res.Footer.Ilegibles[0].Offset != 4096 {
		t.Errorf("Offset = %d", res.Footer.Ilegibles[0].Offset)
	}
}

// TestReproducible: dos ejecuciones con los mismos datos producen manifiestos
// identicos salvo las marcas de tiempo. Es lo que permite comparar versiones.
func TestReproducible(t *testing.T) {
	generar := func() string {
		dir := t.TempDir()
		w, err := Create(dir, Header{Origen: "img.dd", OrigenBytes: 1000, Modo: "carve"})
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 3; i++ {
			e := entrada(int64(i)*100, 50, "hash")
			e.TS = time.Time{} // se rellena sola; se normaliza abajo
			w.Add(e)
		}
		w.Close(true, nil)

		data, _ := os.ReadFile(filepath.Join(dir, Nombre))
		return string(data)
	}

	normalizar := func(s string) []string {
		var out []string
		for _, l := range strings.Split(s, "\n") {
			if l == "" {
				continue
			}
			// Quitar los campos temporales, que por definicion difieren.
			for _, campo := range []string{`"ts":`, `"iniciado":`, `"terminado":`, `"duracion":`} {
				if i := strings.Index(l, campo); i >= 0 {
					fin := strings.IndexByte(l[i:], ',')
					if fin < 0 {
						fin = strings.IndexByte(l[i:], '}')
					}
					if fin > 0 {
						l = l[:i] + l[i+fin+1:]
					}
				}
			}
			out = append(out, l)
		}
		return out
	}

	a, b := normalizar(generar()), normalizar(generar())
	if len(a) != len(b) {
		t.Fatalf("distinto numero de lineas: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Errorf("linea %d difiere:\n  A: %s\n  B: %s", i, a[i], b[i])
		}
	}
}

func TestAddTrasCloseFalla(t *testing.T) {
	w, _ := nuevoWriter(t)
	w.Close(true, nil)

	if err := w.Add(entrada(0, 100, "a")); err == nil {
		t.Error("Add tras Close deberia fallar")
	}
}

func TestCloseEsIdempotente(t *testing.T) {
	w, _ := nuevoWriter(t)
	if err := w.Close(true, nil); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(true, nil); err != nil {
		t.Errorf("el segundo Close deberia ser inocuo: %v", err)
	}
}

func TestConcurrente(t *testing.T) {
	w, path := nuevoWriter(t)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			w.Add(entrada(int64(i)*1000, 100, "h"))
		}(i)
	}
	wg.Wait()
	w.Close(true, nil)

	res, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Entradas) != 50 {
		t.Errorf("%d entradas, se esperaban 50: hubo escrituras entrelazadas", len(res.Entradas))
	}
}

func TestManifiestoSinCabeceraSeRechaza(t *testing.T) {
	path := filepath.Join(t.TempDir(), "malo.jsonl")
	os.WriteFile(path, []byte(`{"tipo":"archivo","offset":0}`+"\n"), 0o644)

	if _, err := Read(path); err == nil {
		t.Error("un manifiesto sin cabecera deberia rechazarse")
	}
}

func TestVersionFuturaSeRechaza(t *testing.T) {
	path := filepath.Join(t.TempDir(), "futuro.jsonl")
	os.WriteFile(path, []byte(`{"tipo":"header","version":9999}`+"\n"), 0o644)

	_, err := Read(path)
	if err == nil {
		t.Fatal("una version futura deberia rechazarse")
	}
	if !strings.Contains(err.Error(), "version") {
		t.Errorf("el error deberia mencionar la version: %v", err)
	}
}

// TestAbortNoEscribeFooter: tras Abort el manifiesto debe parecer interrumpido,
// no completado. Escribir un resumen tras rendirse seria mentir sobre lo que
// paso.
func TestAbortNoEscribeFooter(t *testing.T) {
	w, path := nuevoWriter(t)
	w.Add(entrada(0, 100, "a"))
	if err := w.Abort(); err != nil {
		t.Fatal(err)
	}

	res, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if res.Footer != nil {
		t.Error("Abort no deberia escribir footer")
	}
	if !res.Reanudable() {
		t.Error("un manifiesto abortado debe ser reanudable")
	}
	if len(res.Entradas) != 1 {
		t.Errorf("%d entradas, se esperaba 1", len(res.Entradas))
	}
}

// TestAppendContinuaContadores: al reanudar, el resumen final debe describir el
// trabajo COMPLETO, no solo el ultimo tramo. Si los contadores arrancaran de
// cero, un escaneo interrumpido reportaria menos archivos de los que recupero.
func TestAppendContinuaContadores(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, Nombre)

	// Primer tramo: 3 archivos, uno corrupto.
	w, err := Create(dir, Header{Origen: "img.dd", OrigenBytes: 1000, Modo: "carve"})
	if err != nil {
		t.Fatal(err)
	}
	w.Add(entrada(0, 100, "a"))
	w.Add(entrada(200, 100, "b"))
	malo := entrada(400, 100, "c")
	malo.Validacion = "corrupto"
	w.Add(malo)
	w.Abort() // interrumpido

	previo, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if !previo.Reanudable() {
		t.Fatal("deberia ser reanudable")
	}

	// Segundo tramo: 2 archivos mas.
	w2, err := Append(dir, previo)
	if err != nil {
		t.Fatal(err)
	}
	w2.Add(entrada(600, 100, "d"))
	w2.Add(entrada(800, 100, "e"))
	if err := w2.Close(true, nil); err != nil {
		t.Fatal(err)
	}

	final, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}

	if len(final.Entradas) != 5 {
		t.Errorf("%d entradas, se esperaban 5 (3 + 2)", len(final.Entradas))
	}
	if final.Footer.Archivos != 5 {
		t.Errorf("Footer.Archivos = %d, se esperaban 5: los contadores no continuaron",
			final.Footer.Archivos)
	}
	if final.Footer.Corruptos != 1 {
		t.Errorf("Footer.Corruptos = %d, se esperaba 1 del primer tramo",
			final.Footer.Corruptos)
	}
	if final.Reanudable() {
		t.Error("tras cerrar completo no deberia ser reanudable")
	}
}

// TestAppendRecortaLineaIncompleta: escribir detras de una linea rota produciria
// una linea sintacticamente invalida EN MEDIO del archivo, y eso si impide
// leerlo entero.
func TestAppendRecortaLineaIncompleta(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, Nombre)

	w, _ := Create(dir, Header{Origen: "x", OrigenBytes: 1, Modo: "carve"})
	w.Add(entrada(0, 100, "a"))
	w.Add(entrada(200, 100, "b"))
	w.Abort()

	// Cortar a mitad de la ultima linea.
	data, _ := os.ReadFile(path)
	os.WriteFile(path, data[:len(data)-30], 0o644)

	previo, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}

	w2, err := Append(dir, previo)
	if err != nil {
		t.Fatal(err)
	}
	w2.Add(entrada(400, 100, "c"))
	w2.Close(true, nil)

	// Todas las lineas deben ser JSON valido: si quedara un resto pegado, la
	// lectura se detendria ahi y se perderia todo lo posterior.
	final, err := Read(path)
	if err != nil {
		t.Fatalf("el manifiesto reanudado no se puede leer: %v", err)
	}
	if final.Footer == nil {
		t.Fatal("falta el footer: hubo una linea rota en medio")
	}
	if final.Truncado {
		t.Error("el manifiesto quedo marcado como truncado tras reanudar")
	}
}

// TestRecortarNoCargaElManifiestoEntero es la regresion de un consumo que
// escala con el numero de archivos recuperados.
//
// Con ~386 bytes por entrada, un disco del que se recuperan un millon de
// archivos produce un manifiesto de 386 MB. La version anterior hacia
// os.ReadFile + os.WriteFile para recortar la ultima linea, es decir, lo
// cargaba entero en memoria y lo reescribia, y eso pasaba en CADA reanudacion.
func TestRecortarNoCargaElManifiestoEntero(t *testing.T) {
	if testing.Short() {
		t.Skip("omitido en modo -short")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, Nombre)

	// Manifiesto grande: suficiente para que una lectura completa se
	// distinga con claridad del ruido de medicion. Cada Add hace fsync —es el
	// punto de control para reanudar— asi que no conviene pasarse.
	w, err := Create(dir, Header{Origen: "grande.img", OrigenBytes: 1 << 40, Modo: "carve"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20000; i++ {
		w.Add(entrada(int64(i)*4096, 4096, "hash"))
	}
	w.Abort()

	info, _ := os.Stat(path)
	t.Logf("manifiesto de prueba: %.1f MB", float64(info.Size())/(1<<20))

	// Dejar la ultima linea a medias.
	f, _ := os.OpenFile(path, os.O_RDWR, 0o644)
	f.Truncate(info.Size() - 40)
	f.Close()

	runtime.GC()
	var antes runtime.MemStats
	runtime.ReadMemStats(&antes)

	if err := recortarLineaIncompleta(path); err != nil {
		t.Fatal(err)
	}

	var despues runtime.MemStats
	runtime.ReadMemStats(&despues)
	asignado := despues.TotalAlloc - antes.TotalAlloc
	t.Logf("asignados al recortar: %.2f MB", float64(asignado)/(1<<20))

	// La ventana de busqueda son 64 KB. Un tope de 1 MB separa con holgura el
	// recorte acotado de una lectura completa de 40 MB.
	const tope = 1 << 20
	if asignado > tope {
		t.Errorf("se asignaron %.2f MB para recortar un manifiesto de %.1f MB: "+
			"se esta cargando entero",
			float64(asignado)/(1<<20), float64(info.Size())/(1<<20))
	}

	// Y el resultado debe seguir siendo legible.
	res, err := Read(path)
	if err != nil {
		t.Fatalf("el manifiesto recortado no se puede leer: %v", err)
	}
	if len(res.Entradas) < 19000 {
		t.Errorf("solo %d entradas tras recortar, se perdieron demasiadas", len(res.Entradas))
	}
}

// TestRecortarSinNingunaLineaCompleta: un archivo sin saltos de linea en su
// cola no es un manifiesto. Truncarlo entero destruiria datos, asi que se
// prefiere fallar.
func TestRecortarSinNingunaLineaCompleta(t *testing.T) {
	path := filepath.Join(t.TempDir(), "basura.jsonl")
	if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, 100<<10), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := recortarLineaIncompleta(path); err == nil {
		t.Error("se esperaba error con un archivo sin ninguna linea completa")
	}
}
