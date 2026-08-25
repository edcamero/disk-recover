package carver

import (
	"bytes"
	"testing"

	"github.com/edcamero/disk-recover/internal/signatures"
	"github.com/edcamero/disk-recover/pkg/magic"
)

// TestFragmentedFileSilentCorruption documenta el riesgo mas grave del carving
// por firmas: un archivo FRAGMENTADO.
//
// El carver asume que los datos entre el header y el footer son contiguos. Si
// el sistema de archivos partio el archivo en dos fragmentos con otros datos en
// medio, se extrae header + BASURA + cola, con el footer correcto al final.
// El resultado tiene el tamano y los marcadores de un JPEG valido, pero la
// imagen esta corrupta. No hay ninguna senal de que eso ocurrio.
//
// Este test NO exige un comportamiento correcto: documenta el actual y sirve de
// ancla para cuando se implemente deteccion de fragmentacion.
func TestFragmentedFileSilentCorruption(t *testing.T) {
	// Primer fragmento: cabecera + 4 KB de datos reales.
	head := jpeg(8192)[:4096]
	// Datos ajenos que el FS metio en medio.
	foreign := bytes.Repeat([]byte{0x5A}, 8192)
	// Cola con el footer.
	tail := append(bytes.Repeat([]byte{0x33}, 2048), 0xFF, 0xD9)

	disk := make([]byte, 128<<10)
	copy(disk[1024:], head)
	copy(disk[1024+len(head):], foreign)
	copy(disk[1024+len(head)+len(foreign):], tail)

	reg := signatures.NewRegistry()
	if err := reg.Register(signatures.Signature{
		Name: "jpeg", Extension: ".jpg", Category: "image",
		Header: magic.MustParse("FF D8 FF"), Footer: []byte{0xFF, 0xD9},
		MaxSize: 50 << 20,
	}); err != nil {
		t.Fatal(err)
	}

	w := &memWriter{}
	results, err := New(bytes.NewReader(disk), int64(len(disk)), w, reg).Run()
	if err != nil {
		t.Fatal(err)
	}

	if len(results) != 1 {
		t.Fatalf("se extrajeron %d archivos, se esperaba 1", len(results))
	}

	extracted := w.data[0]
	contaminacion := bytes.Count(extracted, []byte{0x5A})

	t.Logf("extraido: %d bytes, de los cuales %d son datos AJENOS (%.0f%%)",
		len(extracted), contaminacion, float64(contaminacion)*100/float64(len(extracted)))
	t.Logf("empieza por FFD8: %v | termina en FFD9: %v",
		bytes.HasPrefix(extracted, []byte{0xFF, 0xD8}),
		bytes.HasSuffix(extracted, []byte{0xFF, 0xD9}))

	if contaminacion > 0 {
		t.Logf("CONFIRMADO: el archivo extraido tiene marcadores validos pero contenido corrupto, " +
			"y no se emite ninguna advertencia")
	}
}
