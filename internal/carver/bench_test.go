package carver

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/edcamero/disk-recover/internal/output"
	"github.com/edcamero/disk-recover/internal/signatures"
)

// discardWriter cuenta sin escribir en disco, para aislar el coste del escaneo
// del coste de escritura.
type discardWriter struct{ n int }

func (w *discardWriter) Save(r io.Reader, name string) (*output.WriteResult, error) {
	size, err := io.CopyBuffer(io.Discard, r, make([]byte, 1<<20))
	if err != nil {
		return nil, err
	}
	w.n++
	return &output.WriteResult{FinalPath: "/dev/null/" + name, Size: size}, nil
}

// syntheticDisk genera una imagen con densidad de archivos controlada.
//
//	fileEvery: un JPEG cada N bytes (0 = ninguno, solo ruido)
//	noise:     true rellena con datos pseudoaleatorios en vez de ceros
//
// La distinción importa: un disco de ceros es el mejor caso para bytes.Index
// (nunca coincide el primer byte), y uno con ruido es el peor.
func syntheticDisk(size int, fileEvery int, noise bool) []byte {
	disk := make([]byte, size)

	if noise {
		// LCG barato: reproducible y sin coste de crypto/rand.
		var state uint32 = 0x12345678
		for i := range disk {
			state = state*1664525 + 1013904223
			disk[i] = byte(state >> 24)
		}
	}

	if fileEvery > 0 {
		photo := jpeg(64 << 10)
		for off := 0; off+len(photo) < size; off += fileEvery {
			copy(disk[off:], photo)
		}
	}
	return disk
}

func benchScan(b *testing.B, size int, fileEvery int, noise bool) {
	b.Helper()
	disk := syntheticDisk(size, fileEvery, noise)
	reg := signatures.DefaultRegistry()

	b.SetBytes(int64(size))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		w := &discardWriter{}
		c := New(bytes.NewReader(disk), int64(size), w, reg)
		if _, err := c.Run(); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkScanZeros: disco formateado. Mejor caso para la búsqueda.
func BenchmarkScanZeros(b *testing.B) { benchScan(b, 64<<20, 0, false) }

// BenchmarkScanNoise: datos pseudoaleatorios, el peor caso: cada firma tiene
// que descartar muchas coincidencias parciales del primer byte.
func BenchmarkScanNoise(b *testing.B) { benchScan(b, 64<<20, 0, true) }

// BenchmarkScanDense: un archivo cada 1 MB sobre ruido. Mide el coste conjunto
// de encontrar, delimitar (búsqueda de footer) y extraer.
func BenchmarkScanDense(b *testing.B) { benchScan(b, 64<<20, 1<<20, true) }

// BenchmarkScanSparse: un archivo cada 16 MB, más parecido a un disco real.
func BenchmarkScanSparse(b *testing.B) { benchScan(b, 64<<20, 16<<20, true) }

// BenchmarkSingleSignature aisla el coste por firma: con 11 firmas activas el
// bloque se recorre 11 veces.
func BenchmarkSingleSignature(b *testing.B) {
	disk := syntheticDisk(64<<20, 0, true)
	reg := signatures.NewRegistry()
	for _, s := range signatures.DefaultSignatures[:1] {
		reg.Register(s)
	}

	b.SetBytes(int64(len(disk)))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		c := New(bytes.NewReader(disk), int64(len(disk)), &discardWriter{}, reg)
		if _, err := c.Run(); err != nil {
			b.Fatal(err)
		}
	}
}

// TestMemoryCeiling mide el pico real de memoria durante un escaneo, que es la
// afirmación central del diseño: el consumo no debe depender del tamaño del
// origen. Se ejecuta como test y no como benchmark para poder afirmar un límite.
func TestMemoryCeiling(t *testing.T) {
	if testing.Short() {
		t.Skip("prueba de memoria omitida en modo -short")
	}

	// El origen tiene que estar en un ARCHIVO, no en un []byte. Si se usa
	// bytes.NewReader, los datos de prueba viven en el heap de Go y HeapInuse
	// mide la imagen sintetica, no el escaner: con 256 MB de origen daba 270 MB
	// de heap y parecia que el consumo crecia con el disco.
	sizes := []int{16 << 20, 64 << 20, 256 << 20}
	var peaks []uint64

	for _, size := range sizes {
		path := filepath.Join(t.TempDir(), "disco.img")
		if err := os.WriteFile(path, syntheticDisk(size, 4<<20, true), 0o644); err != nil {
			t.Fatal(err)
		}

		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}

		runtime.GC()
		var before runtime.MemStats
		runtime.ReadMemStats(&before)

		c := New(f, int64(size), &discardWriter{}, signatures.DefaultRegistry())
		if _, err := c.Run(); err != nil {
			f.Close()
			t.Fatal(err)
		}

		var after runtime.MemStats
		runtime.ReadMemStats(&after)
		f.Close()

		peaks = append(peaks, after.HeapInuse)
		t.Logf("origen %4d MB -> heap en uso %5.1f MB, asignado durante el escaneo %6.1f MB",
			size>>20,
			float64(after.HeapInuse)/(1<<20),
			float64(after.TotalAlloc-before.TotalAlloc)/(1<<20))

		runtime.GC()
	}

	// El heap vivo NO debe crecer con el tamano del origen: el escaner procesa
	// por bloques con un buffer reutilizado. Es la afirmacion central del diseno.
	if len(peaks) >= 2 {
		first, last := peaks[0], peaks[len(peaks)-1]
		if last > first*4 {
			t.Errorf("el heap crecio de %.1f MB a %.1f MB al multiplicar el origen por %d: "+
				"el consumo depende del tamano del disco",
				float64(first)/(1<<20), float64(last)/(1<<20), sizes[len(sizes)-1]/sizes[0])
		}
	}
}

// TestThroughput1GB mide el rendimiento sobre un volumen de 1 GB, el tamano
// minimo que pide el plan de pruebas. Se salta con -short.
func TestThroughput1GB(t *testing.T) {
	if testing.Short() {
		t.Skip("prueba de 1 GB omitida en modo -short")
	}
	if os.Getenv("DISKRECOVER_BENCH_1GB") == "" {
		t.Skip("define DISKRECOVER_BENCH_1GB=1 para ejecutar la prueba de 1 GB")
	}

	const size = 1 << 30
	disk := syntheticDisk(size, 8<<20, true)

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	w := &discardWriter{}
	c := New(bytes.NewReader(disk), int64(size), w, signatures.DefaultRegistry())

	start := testingNow()
	results, err := c.Run()
	elapsed := testingSince(start)

	if err != nil {
		t.Fatal(err)
	}

	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	mbps := float64(size) / (1 << 20) / elapsed.Seconds()
	t.Logf("1 GB en %v -> %.0f MB/s | %d archivos | heap %.1f MB | asignado %.1f MB",
		elapsed.Round(1e7), mbps, len(results),
		float64(after.HeapInuse)/(1<<20),
		float64(after.TotalAlloc-before.TotalAlloc)/(1<<20))

	fmt.Printf("RESULTADO_1GB throughput_mbps=%.1f archivos=%d heap_mb=%.1f\n",
		mbps, len(results), float64(after.HeapInuse)/(1<<20))
}

// Alias finos sobre time para no importarlo dos veces en el fichero.
func testingNow() time.Time                  { return time.Now() }
func testingSince(t time.Time) time.Duration { return time.Since(t) }
