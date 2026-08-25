package filesystem

import (
	"fmt"
	"io"
	"time"
)

// FileEntry representa un archivo encontrado recorriendo el FS
type FileEntry struct {
	Name        string
	Path        string // ruta relativa desde la raíz del FS
	Offset      int64  // offset en disco donde están los datos
	Size        int64
	IsDir       bool
	ModTime     time.Time
	IsDeleted   bool // true si estaba en espacio "liberado"
	Recoverable bool // true si los clusters son contiguos

	// firstCluster es interno: lo usa el recorrido de directorios para bajar a
	// los subdirectorios sin recalcularlo desde el offset.
	firstCluster uint32
}

// Lister recorre un sistema de archivos dañado tolerando errores
type Lister struct {
	src        io.ReaderAt
	size       int64
	fsType     string // "fat32", "ntfs", "ext4", "unknown"
	onProgress func(percent float64)
}

func NewLister(src io.ReaderAt, size int64) *Lister {
	l := &Lister{src: src, size: size}
	l.fsType = l.detectFilesystem()
	return l
}

// SetProgressCallback establece callback para reportar progreso
func (l *Lister) SetProgressCallback(cb func(float64)) {
	l.onProgress = cb
}

// List recorre el FS y devuelve todos los archivos encontrados
func (l *Lister) List() ([]FileEntry, error) {
	switch l.fsType {
	case "fat32":
		return l.listFAT32()
	case "exfat":
		return l.listExfat()
	case "ntfs":
		return l.listNTFS()
	case "fat16":
		return nil, fmt.Errorf("FAT12/FAT16 detectado pero aún no soportado: usa -mode=carve")
	case "ext4":
		return l.listExt4()
	default:
		return nil, fmt.Errorf("sistema de archivos no reconocido: %s", l.fsType)
	}
}

// detectSize es cuánto leemos para identificar el sistema de archivos. Tiene
// que llegar más allá de 1080, que es donde vive el superbloque de ext4 (offset
// 0x400 + 0x38). Con los 1024 bytes de antes, la comprobación de ext4 estaba
// tras un `len(buf) > 1082` que nunca podía ser cierto.
const detectSize = 2048

// detectFilesystem lee los primeros bytes para identificar el FS.
func (l *Lister) detectFilesystem() string {
	buf := make([]byte, detectSize)
	n, err := l.src.ReadAt(buf, 0)
	if n < 512 {
		return "unknown" // ni siquiera hay un sector de arranque completo
	}
	if err != nil && n < detectSize {
		buf = buf[:n] // lectura parcial: seguimos con lo que haya
	}

	// NTFS: el OEM ID ocupa 8 bytes en el offset 3, y es "NTFS" seguido de
	// cuatro espacios. Compararlo contra buf[3:7] (4 bytes) no podía ser cierto
	// nunca, así que NTFS jamás se detectaba.
	if len(buf) >= 11 && string(buf[3:11]) == "NTFS    " {
		return "ntfs"
	}

	// ext4: magic 0xEF53 en el offset 0x438 (1080), little-endian.
	if len(buf) >= 1082 {
		if uint16(buf[1080])|uint16(buf[1081])<<8 == 0xEF53 {
			return "ext4"
		}
	}

	// exFAT: "EXFAT   " en el offset 3, el mismo sitio donde FAT32 pone su OEM
	// ID. Se comprueba ANTES que FAT porque un volumen exFAT también lleva la
	// firma 0x55AA del final del sector, así que la comprobación de FAT lo
	// reclamaría primero y se intentaría leerlo con un BPB que no tiene.
	if len(buf) >= 11 && string(buf[3:11]) == "EXFAT   " {
		return "exfat"
	}

	// FAT: firma 0x55AA al final del sector de arranque.
	if len(buf) >= 512 && buf[510] == 0x55 && buf[511] == 0xAA {
		// FAT32 declara su tipo en el offset 82.
		if string(buf[82:87]) == "FAT32" {
			return "fat32"
		}
		// FAT12/FAT16 lo declaran en el offset 54. Se devuelven con su propio
		// nombre: comparten el formato de entrada de directorio con FAT32 pero
		// NO el layout del volumen (el directorio raíz está en un área fija, y
		// el campo BPB_RootClus del offset 44 ni siquiera existe). Tratarlos
		// como fat32 producía offsets sin sentido.
		if t := string(buf[54:58]); t == "FAT1" || t == "FAT " {
			return "fat16"
		}
	}

	return "unknown"
}

// FSType devuelve el tipo de FS detectado
func (l *Lister) FSType() string {
	return l.fsType
}
