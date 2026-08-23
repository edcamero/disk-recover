package signatures

import "github.com/edcamero13/disk-recover/pkg/magic"

// Signature describe cómo identificar un tipo de archivo.
type Signature struct {
	Name      string      // "jpeg"
	Extension string      // ".jpg"
	Category  string      // "image", "video", "document", "archive"
	Header    magic.Magic // magic bytes al inicio, con soporte de comodines
	Footer    []byte      // marcador de fin (puede ser nil)
	MaxSize   int64       // límite razonable
}

// DefaultSignatures contiene las firmas soportadas por defecto.
//
// Header es un magic.Magic y no un []byte plano porque varios formatos llevan
// bytes variables en medio de la cabecera. Sin comodines había que recortar la
// firma hasta la parte fija, y eso produce falsos positivos masivos: la firma
// de MP4 era {0x00, 0x00, 0x00}, que coincide con cualquier secuencia de tres
// ceros. En un disco formateado —lleno de ceros por definición— eso son
// millones de coincidencias, cada una pidiendo extraer hasta 4 GB.
var DefaultSignatures = []Signature{
	{
		Name: "jpeg", Extension: ".jpg", Category: "image",
		Header:  magic.MustParse("FF D8 FF"),
		Footer:  []byte{0xFF, 0xD9},
		MaxSize: 50 << 20,
	},
	{
		Name: "png", Extension: ".png", Category: "image",
		Header:  magic.MustParse("89 50 4E 47 0D 0A 1A 0A"),
		Footer:  []byte{0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82},
		MaxSize: 30 << 20,
	},
	{
		Name: "gif", Extension: ".gif", Category: "image",
		Header:  magic.MustParse("47 49 46 38"),
		Footer:  []byte{0x00, 0x3B},
		MaxSize: 20 << 20,
	},
	{
		// "RIFF" + tamaño (4 bytes variables) + "WEBP".
		// Antes webp y avi compartían la firma "RIFF" a secas, así que cada
		// contenedor RIFF se extraía dos veces, una con cada extensión.
		Name: "webp", Extension: ".webp", Category: "image",
		Header:  magic.MustParse("52 49 46 46 ?? ?? ?? ?? 57 45 42 50"),
		MaxSize: 20 << 20,
	},
	{
		Name: "bmp", Extension: ".bmp", Category: "image",
		Header:  magic.MustParse("42 4D"),
		MaxSize: 30 << 20,
	},
	{
		// Tamaño del box (4 bytes variables) + "ftyp".
		Name: "mp4", Extension: ".mp4", Category: "video",
		Header:  magic.MustParse("?? ?? ?? ?? 66 74 79 70"),
		MaxSize: 4 << 30,
	},
	{
		// "RIFF" + tamaño + "AVI " (con espacio final).
		Name: "avi", Extension: ".avi", Category: "video",
		Header:  magic.MustParse("52 49 46 46 ?? ?? ?? ?? 41 56 49 20"),
		MaxSize: 4 << 30,
	},
	{
		Name: "mkv", Extension: ".mkv", Category: "video",
		Header:  magic.MustParse("1A 45 DF A3"),
		MaxSize: 10 << 30,
	},
	{
		// "RIFF" + tamaño + "WAVE".
		Name: "wav", Extension: ".wav", Category: "audio",
		Header:  magic.MustParse("52 49 46 46 ?? ?? ?? ?? 57 41 56 45"),
		MaxSize: 2 << 30,
	},
	{
		Name: "pdf", Extension: ".pdf", Category: "document",
		Header:  magic.MustParse("25 50 44 46 2D"), // "%PDF-"
		Footer:  []byte("%%EOF"),
		MaxSize: 100 << 20,
	},
	{
		Name: "zip", Extension: ".zip", Category: "archive",
		Header:  magic.MustParse("50 4B 03 04"),
		Footer:  []byte{0x50, 0x4B, 0x05, 0x06},
		MaxSize: 10 << 30,
	},
}
