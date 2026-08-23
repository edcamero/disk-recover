package signatures

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/edcamero/disk-recover/pkg/magic"
)

// TestRegistryIndexStability es la regresión de [C9]. La versión anterior
// guardaba &r.signatures[i] en los mapas de índice; en cuanto append supera la
// capacidad reasigna el array y esos punteros quedan apuntando al array viejo.
// Con 8 firmas partiendo de capacidad 0 hay cuatro reasignaciones, así que la
// mayoría del índice estaba desligado.
func TestRegistryIndexStability(t *testing.T) {
	r := NewRegistry()

	names := make([]string, 0, 100)
	for i := 0; i < 100; i++ {
		name := "tipo" + string(rune('a'+i%26)) + strings.Repeat("x", i/26)
		sig := Signature{
			Name:      name,
			Extension: ".bin",
			Category:  "test",
			Header:    magic.New([]byte{byte(i), 0xAA, 0xBB}),
			MaxSize:   int64(i+1) << 20,
		}
		if err := r.Register(sig); err != nil {
			continue // nombre duplicado por la generación, no pasa nada
		}
		names = append(names, name)
	}

	if len(names) < 50 {
		t.Fatalf("solo se registraron %d firmas, muy pocas para la prueba", len(names))
	}

	// Cada firma tiene que seguir siendo consultable y coincidir con lo que
	// devuelve All(), incluidas las registradas ANTES de las reasignaciones.
	all := r.All()
	for i, name := range names {
		got, ok := r.GetByName(name)
		if !ok {
			t.Fatalf("GetByName(%q) no la encontró (índice %d)", name, i)
		}
		if got.Name != name {
			t.Errorf("GetByName(%q) devolvió %q", name, got.Name)
		}
		if got.MaxSize != all[i].MaxSize {
			t.Errorf("firma %q: MaxSize del índice = %d, de All() = %d (índice desligado)",
				name, got.MaxSize, all[i].MaxSize)
		}
	}
}

// TestGetByNameReturnsCopy: mutar lo devuelto no debe alterar el registro.
func TestGetByNameReturnsCopy(t *testing.T) {
	r := DefaultRegistry()

	sig, ok := r.GetByName("jpeg")
	if !ok {
		t.Fatal("no se encontró la firma jpeg")
	}
	original := sig.MaxSize

	sig.MaxSize = 1
	sig.Name = "corrompida"

	again, _ := r.GetByName("jpeg")
	if again.MaxSize != original {
		t.Errorf("mutar la copia cambió el registro: MaxSize = %d, era %d", again.MaxSize, original)
	}
	if again.Name != "jpeg" {
		t.Errorf("mutar la copia cambió el nombre en el registro: %q", again.Name)
	}
}

func TestDefaultRegistryHasNoZeroPrefixSignature(t *testing.T) {
	// Regresión de [C10]: la firma de MP4 era {0x00,0x00,0x00}, que coincide
	// con cualquier secuencia de tres ceros. En un disco formateado eso son
	// millones de falsos positivos, cada uno pidiendo extraer hasta 4 GB.
	zeros := make([]byte, 64)

	for _, sig := range DefaultRegistry().All() {
		if idx := sig.Header.Find(zeros); idx >= 0 {
			t.Errorf("la firma %q coincide con una región de ceros (header %s): "+
				"produciría falsos positivos masivos en un disco formateado",
				sig.Name, sig.Header)
		}
	}
}

func TestDefaultRegistryNoDuplicateHeaders(t *testing.T) {
	// Regresión de [I21]: webp y avi compartían "RIFF" a secas, así que cada
	// contenedor RIFF se extraía dos veces con extensiones distintas.
	all := DefaultRegistry().All()
	for i := range all {
		for j := i + 1; j < len(all); j++ {
			if all[i].Header.Equal(all[j].Header) {
				t.Errorf("las firmas %q y %q comparten header %s",
					all[i].Name, all[j].Name, all[i].Header)
			}
		}
	}
}

func TestParseSize(t *testing.T) {
	tests := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{"1024", 1024, false},
		{"50MB", 50 << 20, false},
		{"4GB", 4 << 30, false},
		{"1TB", 1 << 40, false},
		{"512KB", 512 << 10, false},
		{"100B", 100, false},

		// Regresión de [I14]: fmt.Sscanf("%d") se paraba en el primer carácter
		// no numérico SIN error, así que "12xyz" devolvía 12 en silencio.
		{"12xyz", 0, true},
		{"5 foo", 0, true},
		{"abc", 0, true},
		{"", 0, true},
		{"-5MB", 0, true},
	}

	for _, tt := range tests {
		got, err := parseSize(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("parseSize(%q) error = %v, wantErr = %v", tt.in, err, tt.wantErr)
			continue
		}
		if err == nil && got != tt.want {
			t.Errorf("parseSize(%q) = %d, se esperaba %d", tt.in, got, tt.want)
		}
	}
}

// TestLoadFromReaderIsTransactional es la regresión de [M6]: un error a mitad
// del archivo dejaba registradas las firmas anteriores.
func TestLoadFromReaderIsTransactional(t *testing.T) {
	r := NewRegistry()

	input := `
name: buena1
ext: .b1
header: ff d8 ff
---
name: buena2
ext: .b2
header: 89 50 4e 47
---
name: mala
header: NO_ES_HEX
`
	if err := r.LoadFromReader(strings.NewReader(input)); err == nil {
		t.Fatal("se esperaba error por el header inválido")
	}

	if n := r.Count(); n != 0 {
		t.Errorf("quedaron %d firmas registradas tras el fallo, se esperaban 0", n)
	}
}

func TestLoadFromReaderWildcards(t *testing.T) {
	r := NewRegistry()
	input := "name: mp4custom\next: .mp4\nheader: ?? ?? ?? ?? 66 74 79 70\nmaxsize: 4GB\n"

	if err := r.LoadFromReader(strings.NewReader(input)); err != nil {
		t.Fatalf("LoadFromReader: %v", err)
	}

	sig, ok := r.GetByName("mp4custom")
	if !ok {
		t.Fatal("no se registró mp4custom")
	}
	if sig.MaxSize != 4<<30 {
		t.Errorf("MaxSize = %d, se esperaba %d", sig.MaxSize, int64(4)<<30)
	}

	data := []byte{0x11, 0x22, 0x00, 0x00, 0x00, 0x18, 'f', 't', 'y', 'p', 'i', 's', 'o', 'm'}
	if idx := sig.Header.Find(data); idx != 2 {
		t.Errorf("Find() = %d, se esperaba 2", idx)
	}
}

// TestFilterDoesNotDeadlock es la regresión de [I16]: Filter evaluaba el
// predicado con el RLock tomado, así que un predicado que consultara el
// registro hacía RLock recursivo y se bloqueaba en cuanto había un escritor
// esperando.
func TestFilterDoesNotDeadlock(t *testing.T) {
	r := DefaultRegistry()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Predicado que vuelve a entrar en el registro.
		r.Filter(func(s Signature) bool {
			_, ok := r.GetByName(s.Name)
			return ok
		})
	}()

	// Escritor concurrente, que es lo que dispara el deadlock.
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r.Register(Signature{
				Name:   "extra" + string(rune('a'+i)),
				Header: magic.New([]byte{byte(i), 0x01}),
			})
		}(i)
	}
	wg.Wait()

	select {
	case <-done:
	case <-timeoutAfterSeconds(10):
		t.Fatal("Filter se bloqueó: deadlock por RLock recursivo")
	}
}

func TestRegistryConcurrentAccess(t *testing.T) {
	r := DefaultRegistry()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r.GetByName("jpeg")
			r.All()
			r.Count()
			r.GetByExtension(".png")
			r.FilterByCategory("image")
			r.Register(Signature{
				Name:   "concurrente" + string(rune('a'+i%26)),
				Header: magic.New([]byte{byte(i), 0xFE}),
			})
		}(i)
	}
	wg.Wait()
}

func timeoutAfterSeconds(n int) <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		time.Sleep(time.Duration(n) * time.Second)
		close(ch)
	}()
	return ch
}
