package carver

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	"github.com/edcamero/disk-recover/internal/output"
	"github.com/edcamero/disk-recover/internal/signatures"
	"github.com/edcamero/disk-recover/pkg/magic"
)

type alignedReader struct {
	data   []byte
	sector int64
	bad    []string
}

func (r *alignedReader) ReadAt(p []byte, off int64) (int, error) {
	if off%r.sector != 0 || int64(len(p))%r.sector != 0 {
		r.bad = append(r.bad, fmt.Sprintf("off=%d len=%d", off, len(p)))
		return 0, fmt.Errorf("ERROR_INVALID_PARAMETER")
	}
	if off >= int64(len(r.data)) {
		return 0, io.EOF
	}
	n := copy(p, r.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// alignedWriter imita a output.SafeWriter: io.CopyBuffer con buffer de 1 MB.
type alignedWriter struct{ buf bytes.Buffer }

func (w *alignedWriter) Save(r io.Reader, name string) (*output.WriteResult, error) {
	w.buf.Reset()
	n, err := io.CopyBuffer(&w.buf, r, make([]byte, 1<<20))
	if err != nil {
		return nil, err
	}
	return &output.WriteResult{FinalPath: "/mem/" + name, Size: n}, nil
}

func TestRawDeviceAlignment(t *testing.T) {
	// Tamaño de foto NO múltiplo de 512, que es lo normal.
	photo := jpeg(300<<10 + 137)
	disk := make([]byte, 3*blockSize)
	copy(disk[4096:], photo)

	src := &alignedReader{data: disk, sector: 512}
	reg := signatures.NewRegistry()
	reg.Register(signatures.Signature{
		Name: "jpeg", Extension: ".jpg", Category: "image",
		Header: magic.MustParse("FF D8 FF"), Footer: []byte{0xFF, 0xD9},
		MaxSize: 50 << 20,
	})

	c := New(src, int64(len(disk)), &alignedWriter{}, reg)
	results, err := c.Run()

	t.Logf("recuperados=%d err=%v", len(results), err)
	t.Logf("lecturas NO alineadas: %d", len(src.bad))
	for i, b := range src.bad {
		if i >= 5 {
			t.Logf("  ... y %d más", len(src.bad)-5)
			break
		}
		t.Logf("  %s", b)
	}
	if len(src.bad) > 0 {
		t.Errorf("fallarian en un dispositivo en crudo de Windows")
	}
}
