package filesystem

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"
)

// =========================================================================
// Constructor de imagenes exFAT sinteticas
// =========================================================================

const (
	exTestSectorShift  = 9 // 512 bytes
	exTestClusterShift = 3 // 8 sectores = 4096 bytes por cluster
)

type exfatImage struct {
	data        []byte
	clusterSize int64
	fatOffset   int64
	heapOffset  int64
}

// newExfatImage construye un volumen exFAT minimo pero coherente.
//
// exFAT guarda los tamanos como EXPONENTES de dos, no como valores: el campo
// del offset 108 vale 9 para sectores de 512 bytes. Escribirlo como 512 daria
// un sector de 2^512 y nada cuadraria.
func newExfatImage(clusters int) *exfatImage {
	sectorSize := int64(1) << exTestSectorShift
	clusterSize := sectorSize << exTestClusterShift

	fatSector := int64(128)
	fatSectores := int64(64)
	heapSector := fatSector + fatSectores

	total := (heapSector * sectorSize) + int64(clusters+2)*clusterSize

	img := &exfatImage{
		data:        make([]byte, total),
		clusterSize: clusterSize,
		fatOffset:   fatSector * sectorSize,
		heapOffset:  heapSector * sectorSize,
	}

	boot := img.data[:512]
	copy(boot[3:11], "EXFAT   ")
	binary.LittleEndian.PutUint32(boot[80:84], uint32(fatSector))
	binary.LittleEndian.PutUint32(boot[84:88], uint32(fatSectores))
	binary.LittleEndian.PutUint32(boot[88:92], uint32(heapSector))
	binary.LittleEndian.PutUint32(boot[92:96], uint32(clusters))
	binary.LittleEndian.PutUint32(boot[96:100], 2) // cluster raiz
	boot[108] = exTestSectorShift
	boot[109] = exTestClusterShift
	boot[510], boot[511] = 0x55, 0xAA

	// Toda cadena termina en su primer cluster salvo indicacion contraria.
	for c := 2; c < clusters+2; c++ {
		off := img.fatOffset + int64(c)*4
		if off+4 <= int64(len(img.data)) {
			binary.LittleEndian.PutUint32(img.data[off:off+4], 0xFFFFFFFF)
		}
	}

	return img
}

func (i *exfatImage) clusterOffset(c uint32) int64 {
	return i.heapOffset + int64(c-2)*i.clusterSize
}

func (i *exfatImage) writeAt(c uint32, data []byte) {
	off := i.clusterOffset(c)
	if off+int64(len(data)) <= int64(len(i.data)) {
		copy(i.data[off:], data)
	}
}

func (i *exfatImage) size() int64 { return int64(len(i.data)) }

// exfatFileSet construye el conjunto de entradas de un archivo:
// principal (0x85) + stream (0xC0) + una o mas de nombre (0xC1).
func exfatFileSet(nombre string, cluster uint32, size int64, dir, borrado, contiguo bool) []byte {
	runas := utf16.Encode([]rune(nombre))
	entradasNombre := (len(runas) + exfatCharsPerNameEntry - 1) / exfatCharsPerNameEntry
	if entradasNombre == 0 {
		entradasNombre = 1
	}
	secundarias := 1 + entradasNombre

	out := make([]byte, (secundarias+1)*dirEntrySize)

	// Entrada principal.
	principal := out[0:32]
	if borrado {
		principal[0] = exfatEntryFileDeleted
	} else {
		principal[0] = exfatEntryFile
	}
	principal[1] = byte(secundarias)
	var attrs uint16
	if dir {
		attrs |= exfatAttrDirectory
	}
	binary.LittleEndian.PutUint16(principal[4:6], attrs)
	binary.LittleEndian.PutUint16(principal[12:14], uint16((2024-1980)<<9|6<<5|15))

	// Entrada de stream.
	stream := out[32:64]
	stream[0] = exfatEntryStream
	if borrado {
		stream[0] &^= 0x80 // al borrar tambien se apaga el bit de "en uso"
	}
	if contiguo {
		stream[1] |= 0x02 // NoFatChain
	}
	stream[3] = byte(len(runas)) // NameLength
	binary.LittleEndian.PutUint64(stream[8:16], uint64(size))
	binary.LittleEndian.PutUint32(stream[20:24], cluster)

	// Entradas de nombre.
	for e := 0; e < entradasNombre; e++ {
		ent := out[64+e*32 : 64+(e+1)*32]
		ent[0] = exfatEntryName
		if borrado {
			ent[0] &^= 0x80
		}
		for c := 0; c < exfatCharsPerNameEntry; c++ {
			idx := e*exfatCharsPerNameEntry + c
			if idx >= len(runas) {
				break
			}
			binary.LittleEndian.PutUint16(ent[2+c*2:4+c*2], runas[idx])
		}
	}

	return out
}

// =========================================================================
// Deteccion
// =========================================================================

// TestDetectExfat: exFAT lleva TAMBIEN la firma 0x55AA, asi que si se
// comprobara FAT primero un volumen exFAT se leeria con un BPB que no tiene.
func TestDetectExfat(t *testing.T) {
	img := newExfatImage(8)
	l := NewLister(bytes.NewReader(img.data), img.size())

	if got := l.FSType(); got != "exfat" {
		t.Errorf("FSType() = %q, se esperaba %q", got, "exfat")
	}
}

func TestDetectExfatNoSeConfundeConFAT32(t *testing.T) {
	// Un volumen FAT32 real no debe detectarse como exFAT.
	fat := newFAT32Image(8)
	l := NewLister(bytes.NewReader(fat.data), fat.size())

	if got := l.FSType(); got != "fat32" {
		t.Errorf("un volumen FAT32 se detecto como %q", got)
	}
}

// =========================================================================
// Validacion de la cabecera
// =========================================================================

func TestExfatBootValidation(t *testing.T) {
	casos := []struct {
		nombre string
		romper func(boot []byte)
	}{
		{"exponente de sector absurdo", func(b []byte) { b[108] = 200 }},
		{"exponente de sector demasiado bajo", func(b []byte) { b[108] = 3 }},
		{"exponente de cluster absurdo", func(b []byte) { b[109] = 99 }},
		{"cluster raiz invalido", func(b []byte) { binary.LittleEndian.PutUint32(b[96:100], 1) }},
		{"heap fuera del volumen", func(b []byte) { binary.LittleEndian.PutUint32(b[88:92], 0xFFFFFF) }},
		{"FAT fuera del volumen", func(b []byte) { binary.LittleEndian.PutUint32(b[80:84], 0xFFFFFF) }},
	}

	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			img := newExfatImage(8)
			c.romper(img.data[:512])

			l := NewLister(bytes.NewReader(img.data), img.size())
			if _, err := l.listExfat(); err == nil {
				t.Error("se esperaba error explicito, se acepto una cabecera corrupta")
			}
		})
	}
}

// TestExfatExponentesNoSonValores documenta el error mas facil de cometer al
// implementar exFAT: tratar los exponentes como si fueran valores directos.
func TestExfatExponentesNoSonValores(t *testing.T) {
	img := newExfatImage(8)

	p, err := parseExfatBoot(bytes.NewReader(img.data), img.size())
	if err != nil {
		t.Fatal(err)
	}

	if p.bytesPerSector != 512 {
		t.Errorf("bytesPerSector = %d, se esperaba 512 (2^9)", p.bytesPerSector)
	}
	if p.sectorsPerCluster != 8 {
		t.Errorf("sectorsPerCluster = %d, se esperaba 8 (2^3)", p.sectorsPerCluster)
	}
	if p.clusterSize != 4096 {
		t.Errorf("clusterSize = %d, se esperaba 4096", p.clusterSize)
	}
}

// =========================================================================
// Recorrido
// =========================================================================

func TestExfatNombreLargoUnicode(t *testing.T) {
	img := newExfatImage(16)

	// Un nombre de mas de 15 caracteres ocupa dos entradas 0xC1, y con acentos
	// se comprueba que la decodificacion UTF-16 es correcta.
	nombre := "Vacaciones en Cádiz 2024.jpg"
	img.writeAt(2, exfatFileSet(nombre, 3, 4096, false, false, true))

	l := NewLister(bytes.NewReader(img.data), img.size())
	entries, err := l.listExfat()
	if err != nil {
		t.Fatal(err)
	}

	if len(entries) != 1 {
		var n []string
		for _, e := range entries {
			n = append(n, e.Name)
		}
		t.Fatalf("%d entradas, se esperaba 1: %v", len(entries), n)
	}
	if entries[0].Name != nombre {
		t.Errorf("Name = %q, se esperaba %q", entries[0].Name, nombre)
	}
	if entries[0].Size != 4096 {
		t.Errorf("Size = %d, se esperaba 4096", entries[0].Size)
	}
	if !entries[0].Recoverable {
		t.Error("Recoverable = false con NoFatChain activo: los datos son contiguos")
	}
}

// TestExfatNoFatChainDecideRecoverable: sin el bit de contiguidad no se puede
// afirmar donde estan los datos con un unico Offset, asi que no debe marcarse
// recuperable. Marcarlo produciria archivos con contenido de otro sitio.
func TestExfatNoFatChainDecideRecoverable(t *testing.T) {
	img := newExfatImage(16)
	img.writeAt(2, exfatFileSet("fragmentado.jpg", 3, 8192, false, false, false))

	l := NewLister(bytes.NewReader(img.data), img.size())
	entries, err := l.listExfat()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("%d entradas, se esperaba 1", len(entries))
	}
	if entries[0].Recoverable {
		t.Error("Recoverable = true sin NoFatChain: se extraerian datos ajenos")
	}
}

func TestExfatEntradaBorrada(t *testing.T) {
	img := newExfatImage(16)
	img.writeAt(2, exfatFileSet("borrada.jpg", 3, 2048, false, true, true))

	l := NewLister(bytes.NewReader(img.data), img.size())
	entries, err := l.listExfat()
	if err != nil {
		t.Fatal(err)
	}

	if len(entries) != 1 {
		t.Fatalf("%d entradas, se esperaba 1", len(entries))
	}
	if !entries[0].IsDeleted {
		t.Error("IsDeleted = false en una entrada borrada")
	}
	// exFAT no pisa ningun caracter del nombre al borrar, solo el bit de uso:
	// el nombre se recupera INTACTO, a diferencia de FAT32.
	if entries[0].Name != "borrada.jpg" {
		t.Errorf("Name = %q, se esperaba el nombre intacto", entries[0].Name)
	}
}

func TestExfatVariosArchivos(t *testing.T) {
	img := newExfatImage(32)

	var dir []byte
	dir = append(dir, exfatFileSet("uno.jpg", 3, 1000, false, false, true)...)
	dir = append(dir, exfatFileSet("dos.png", 4, 2000, false, false, true)...)
	dir = append(dir, exfatFileSet("tres.pdf", 5, 3000, false, false, true)...)
	img.writeAt(2, dir)

	l := NewLister(bytes.NewReader(img.data), img.size())
	entries, err := l.listExfat()
	if err != nil {
		t.Fatal(err)
	}

	if len(entries) != 3 {
		var n []string
		for _, e := range entries {
			n = append(n, e.Name)
		}
		t.Fatalf("%d entradas, se esperaban 3: %v", len(entries), n)
	}
	esperados := []string{"uno.jpg", "dos.png", "tres.pdf"}
	for i, want := range esperados {
		if entries[i].Name != want {
			t.Errorf("entrada %d: Name = %q, se esperaba %q", i, entries[i].Name, want)
		}
	}
}

// TestExfatConjuntoCorruptoNoRompeElRecorrido: un SecondaryCount absurdo no debe
// hacer que se pierda el resto del directorio.
func TestExfatConjuntoCorruptoNoRompeElRecorrido(t *testing.T) {
	img := newExfatImage(32)

	malo := exfatFileSet("malo.jpg", 3, 1000, false, false, true)
	malo[1] = 200 // SecondaryCount imposible

	var dir []byte
	dir = append(dir, malo...)
	dir = append(dir, exfatFileSet("bueno.jpg", 4, 2000, false, false, true)...)
	img.writeAt(2, dir)

	l := NewLister(bytes.NewReader(img.data), img.size())
	entries, err := l.listExfat()
	if err != nil {
		t.Fatal(err)
	}

	encontrado := false
	for _, e := range entries {
		if e.Name == "bueno.jpg" {
			encontrado = true
		}
	}
	if !encontrado {
		t.Error("un conjunto corrupto hizo perder el archivo siguiente")
	}
}

// TestExfatDirectorioCiclicoTermina: la misma proteccion que en FAT32.
func TestExfatDirectorioCiclicoTermina(t *testing.T) {
	img := newExfatImage(16)
	// Un directorio que se apunta a si mismo.
	img.writeAt(2, exfatFileSet("bucle", 2, 0, true, false, true))

	l := NewLister(bytes.NewReader(img.data), img.size())

	done := make(chan struct{})
	go func() {
		l.listExfat()
		close(done)
	}()

	select {
	case <-done:
	case <-timeoutAfterSeconds(15):
		t.Fatal("un directorio exFAT autorreferente provoco recursion infinita")
	}
}

func TestExfatNoHacePanicConBasura(t *testing.T) {
	for seed := 0; seed < 200; seed++ {
		img := newExfatImage(8)
		// Llenar el cluster raiz de basura reproducible.
		off := img.clusterOffset(2)
		for i := int64(0); i < img.clusterSize && off+i < int64(len(img.data)); i++ {
			img.data[off+i] = byte((int64(seed)*7 + i*13) % 256)
		}

		l := NewLister(bytes.NewReader(img.data), img.size())
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic con semilla %d: %v", seed, r)
				}
			}()
			l.listExfat()
		}()
	}
}

func FuzzParseExfatFileSet(f *testing.F) {
	f.Add(exfatFileSet("a.jpg", 3, 100, false, false, true))
	f.Add([]byte{exfatEntryFile})
	f.Add([]byte{})

	p := &exfatParams{
		bytesPerSector: 512, sectorsPerCluster: 8, clusterSize: 4096,
		clusterHeapOffset: 65536, rootCluster: 2,
	}
	l := &Lister{size: 1 << 30}

	f.Fuzz(func(t *testing.T, data []byte) {
		fe, n := l.parseExfatFileSet(data, p, false) // no debe hacer panic
		if n < 0 {
			t.Fatalf("consumidos negativo: %d", n)
		}
		if fe != nil && fe.Recoverable {
			if fe.Offset <= 0 || fe.Size <= 0 || fe.Offset+fe.Size > l.size {
				t.Fatalf("recuperable incoherente: offset=%d size=%d", fe.Offset, fe.Size)
			}
		}
	})
}

// verificarNombreLimpio deja constancia de que los nombres no arrastran relleno.
func TestExfatNameLengthRecortaRelleno(t *testing.T) {
	img := newExfatImage(16)

	set := exfatFileSet("corto.jpg", 3, 100, false, false, true)
	// Las entradas de nombre tienen 15 huecos; "corto.jpg" usa 9. Si no se
	// respetara NameLength, se arrastraria el relleno.
	img.writeAt(2, set)

	l := NewLister(bytes.NewReader(img.data), img.size())
	entries, _ := l.listExfat()

	if len(entries) != 1 {
		t.Fatalf("%d entradas", len(entries))
	}
	if n := entries[0].Name; n != "corto.jpg" || strings.ContainsRune(n, 0) {
		t.Errorf("Name = %q: arrastra relleno", n)
	}
}
