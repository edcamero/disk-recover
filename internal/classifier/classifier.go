// Package classifier decide si un archivo recuperado es contenido del usuario
// (una foto, un vídeo personal) o ruido del sistema (iconos, recursos de
// programas, miniaturas). Es la capa que separa esta herramienta de un carver
// clásico, que devuelve las fotos de vacaciones mezcladas con 50.000 iconos.
package classifier

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// headerBytes es cuánto leemos de cada archivo. El APP1 de EXIF no puede pasar
// de 64 KB por segmento y el SOF viene poco después, así que 256 KB cubre el
// caso peor sin cargar un vídeo de 4 GB en memoria.
const headerBytes = 256 << 10

// Categorías que produce el clasificador.
const (
	CategoryPhoto      = "photo"
	CategoryScreenshot = "screenshot"
	CategoryGraphic    = "graphic"
	CategoryIcon       = "icon"
	CategoryDocument   = "document"
	CategoryVideo      = "video"
	CategoryUnknown    = "unknown"
)

// Result es el veredicto sobre un archivo. Se serializa junto al archivo
// recuperado como .meta.json, así que los nombres JSON son parte de la salida.
type Result struct {
	Category      string   `json:"category"`
	IsUserContent bool     `json:"is_user_content"`
	Confidence    float64  `json:"confidence"` // confianza EN EL VEREDICTO, [0,1]
	Reasons       []string `json:"reasons"`

	SizeBytes int64 `json:"size_bytes"`
	Offset    int64 `json:"offset"`
	Width     int   `json:"width,omitempty"`
	Height    int   `json:"height,omitempty"`

	HasEXIF  bool   `json:"has_exif"`
	Camera   string `json:"camera,omitempty"`
	Software string `json:"software,omitempty"`
	HasGPS   bool   `json:"has_gps"`

	// Puntero a propósito: omitempty no funciona sobre un time.Time por valor
	// (no es un "empty value" para encoding/json), así que una fecha ausente se
	// serializaba como "0001-01-01T00:00:00Z" en el .meta.json.
	DateTaken *time.Time `json:"date_taken,omitempty"`
}

// Classifier no guarda estado entre llamadas; el tipo existe para poder
// inyectar configuración más adelante sin romper la API.
type Classifier struct {
	// UserThreshold es el score a partir del cual algo se considera del
	// usuario. 0.5 por defecto.
	UserThreshold float64
}

// New crea un clasificador con los umbrales por defecto.
func New() *Classifier {
	return &Classifier{UserThreshold: 0.5}
}

// Classify analiza el archivo en path y emite un veredicto. offset es la
// posición original en el disco, que se propaga al .meta.json para poder
// correlacionar con el escaneo.
func (c *Classifier) Classify(path string, offset int64) (*Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("classifier: no se pudo abrir %s: %w", path, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("classifier: no se pudo obtener el tamaño de %s: %w", path, err)
	}
	size := info.Size()

	toRead := int64(headerBytes)
	if size < toRead {
		toRead = size
	}
	header := make([]byte, toRead)
	// Lectura parcial: un archivo truncado sigue siendo clasificable.
	n, _ := f.ReadAt(header, 0)
	header = header[:n]

	res := &Result{
		Category:  CategoryUnknown,
		SizeBytes: size,
		Offset:    offset,
	}

	var ex exifData
	parseEXIF(header, &ex)

	res.HasEXIF = ex.HasEXIF
	res.HasGPS = ex.HasGPS
	res.Software = ex.Software
	res.Camera = cameraName(ex.Make, ex.Model)
	if !ex.DateTaken.IsZero() {
		taken := ex.DateTaken
		res.DateTaken = &taken
	}

	if w, h, ok := readDimensions(header); ok {
		res.Width, res.Height = w, h
	} else if ex.Width > 0 && ex.Height > 0 {
		res.Width, res.Height = ex.Width, ex.Height
	}

	score := c.score(res, &ex, strings.ToLower(filepath.Ext(path)))

	res.IsUserContent = score >= c.UserThreshold
	// Confianza en el veredicto: 0 justo en la frontera, 1 en los extremos.
	res.Confidence = (score - 0.5) * 2
	if res.Confidence < 0 {
		res.Confidence = -res.Confidence
	}

	return res, nil
}

// score calcula la probabilidad de que esto sea contenido del usuario, en [0,1].
// Parte de 0.5 (sin información) y acumula evidencia en ambos sentidos.
func (c *Classifier) score(res *Result, ex *exifData, ext string) float64 {
	score := 0.5
	add := func(delta float64, reason string) {
		score += delta
		res.Reasons = append(res.Reasons, reason)
	}

	// --- Evidencia fuerte de contenido del usuario -------------------------

	// Ningún icono ni recurso de programa lleva marca y modelo de cámara.
	if ex.hasCameraInfo() {
		add(0.40, "EXIF con cámara: "+res.Camera)
		res.Category = CategoryPhoto
	}
	if ex.HasGPS {
		add(0.25, "coordenadas GPS presentes")
		res.Category = CategoryPhoto
	}
	if !ex.DateTaken.IsZero() {
		add(0.10, "fecha de captura: "+ex.DateTaken.Format("2006-01-02"))
	}

	// --- Evidencia por dimensiones ----------------------------------------

	if res.Width > 0 && res.Height > 0 {
		switch {
		case isIconSize(res.Width, res.Height):
			add(-0.40, fmt.Sprintf("dimensiones de icono (%dx%d)", res.Width, res.Height))
			if res.Category == CategoryUnknown {
				res.Category = CategoryIcon
			}
		case res.Width < 200 && res.Height < 200:
			add(-0.20, fmt.Sprintf("imagen muy pequeña (%dx%d)", res.Width, res.Height))
		case res.Width >= 1200 || res.Height >= 1200:
			add(0.20, fmt.Sprintf("resolución alta (%dx%d)", res.Width, res.Height))
		}

		if isScreenSize(res.Width, res.Height) && !ex.hasCameraInfo() {
			add(0.05, "resolución de pantalla común: posible captura")
			if res.Category == CategoryUnknown {
				res.Category = CategoryScreenshot
			}
		} else if isPhotoAspect(res.Width, res.Height) && (res.Width >= 800 || res.Height >= 800) {
			add(0.10, "proporción típica de fotografía")
		}
	}

	// --- Evidencia por tamaño ---------------------------------------------

	switch {
	case res.SizeBytes < 20<<10:
		add(-0.20, "archivo muy pequeño (<20 KB)")
	case res.SizeBytes >= 1<<20:
		add(0.15, "archivo grande (>=1 MB)")
	case res.SizeBytes >= 300<<10:
		add(0.05, "archivo mediano (>=300 KB)")
	}

	// --- Ajustes por tipo --------------------------------------------------

	switch ext {
	case ".jpg", ".jpeg":
		// El JPEG es formato de cámara; casi nadie lo usa para iconos.
		if !ex.HasEXIF {
			add(-0.05, "JPEG sin EXIF")
		}
	case ".png", ".gif", ".webp":
		// Formatos dominantes en recursos de interfaz.
		if !ex.HasEXIF && res.SizeBytes < 100<<10 {
			add(-0.15, "formato de interfaz, sin EXIF y pequeño")
		}
	case ".mp4", ".avi", ".mov", ".mkv":
		add(0.20, "archivo de vídeo")
		if res.Category == CategoryUnknown {
			res.Category = CategoryVideo
		}
	case ".pdf", ".doc", ".docx":
		add(0.10, "documento")
		if res.Category == CategoryUnknown {
			res.Category = CategoryDocument
		}
	}

	// Clamp final.
	if score < 0 {
		score = 0
	}
	if score > 1 {
		score = 1
	}

	// Si nada decidió la categoría, deducirla del veredicto.
	if res.Category == CategoryUnknown && score >= c.UserThreshold {
		res.Category = CategoryGraphic
	}

	return score
}

// cameraName combina marca y modelo sin repetirlos.
//
// Muchas cámaras ponen el fabricante en los dos campos: Nikon graba
// Make="NIKON CORPORATION" y Model="NIKON Z 6". Concatenarlos a secas produce
// "NIKON CORPORATION NIKON Z 6", que acaba en el .meta.json a la vista del
// usuario.
func cameraName(make, model string) string {
	make = strings.TrimSpace(make)
	model = strings.TrimSpace(model)

	switch {
	case make == "":
		return model
	case model == "":
		return make
	case strings.EqualFold(make, model):
		return make
	}

	// El modelo ya incluye la marca (o su primera palabra): basta el modelo.
	firstWord := make
	if i := strings.IndexByte(make, ' '); i > 0 {
		firstWord = make[:i]
	}
	if strings.HasPrefix(strings.ToUpper(model), strings.ToUpper(firstWord)) {
		return model
	}

	return make + " " + model
}

// iconSizes son los lados habituales de iconos y miniaturas de sistema.
var iconSizes = map[int]bool{
	16: true, 20: true, 24: true, 32: true, 40: true, 48: true,
	64: true, 72: true, 96: true, 128: true, 144: true, 192: true,
	256: true, 512: true,
}

// isIconSize: cuadrado y de lado "redondo". Un icono de 32x32 es
// inequívocamente un recurso; una foto cuadrada de 1080x1080 no lo es.
func isIconSize(w, h int) bool {
	return w == h && iconSizes[w]
}

// isScreenSize reconoce resoluciones de pantalla comunes, señal de captura.
func isScreenSize(w, h int) bool {
	type res struct{ w, h int }
	common := []res{
		{1280, 720}, {1366, 768}, {1440, 900}, {1600, 900},
		{1920, 1080}, {2560, 1440}, {3840, 2160}, {2880, 1800},
		{1024, 768}, {1280, 800}, {1512, 982}, {3024, 1964},
	}
	for _, r := range common {
		if (w == r.w && h == r.h) || (w == r.h && h == r.w) {
			return true
		}
	}
	return false
}

// isPhotoAspect comprueba si la proporción se acerca a 4:3, 3:2 o 16:9, que son
// las que producen las cámaras y los teléfonos.
func isPhotoAspect(w, h int) bool {
	if w <= 0 || h <= 0 {
		return false
	}
	ratio := float64(w) / float64(h)
	if ratio < 1 {
		ratio = 1 / ratio
	}
	for _, target := range []float64{4.0 / 3.0, 3.0 / 2.0, 16.0 / 9.0} {
		if diff := ratio - target; diff < 0.03 && diff > -0.03 {
			return true
		}
	}
	return false
}
