package filesystem

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
)

// Soporte de exFAT.
//
// Es el hueco de portabilidad mas caro del proyecto: Windows formatea en exFAT
// toda unidad extraible de mas de 32 GB, y es el formato por defecto de las
// tarjetas SDXC de camara. El caso de uso central —recuperar fotos de un USB o
// una tarjeta— cae mayoritariamente aqui, y sin esto terminaba en modo carve
// perdiendo todos los nombres.
//
// exFAT no es "FAT32 con nombres mas largos": cambia lo esencial.
//
//	                   FAT32                    exFAT
//	entrada dir        32 bytes, autocontenida  conjunto de 32 bytes encadenados
//	nombre             8.3 + LFN opcional       siempre UTF-16, en entradas 0xC1
//	tamano             en la entrada            en la entrada de stream (0xC0)
//	contiguidad        siempre por cadena FAT   bit NoFatChain: puede ser directa
//	sector de arranque BPB clasico              cabecera propia con exponentes
//
// El bit NoFatChain es lo que mas importa aqui: cuando esta activo, los datos
// son contiguos desde el primer cluster y se pueden extraer sin recorrer la FAT.

const (
	// Tipos de entrada de directorio en exFAT. El bit 0x80 marca "en uso".
	exfatEntryBitmap    = 0x81
	exfatEntryUpcase    = 0x82
	exfatEntryVolumeLbl = 0x83
	exfatEntryFile      = 0x85
	exfatEntryStream    = 0xC0
	exfatEntryName      = 0xC1

	// Un tipo con el bit 0x80 a cero es la misma entrada marcada como borrada.
	exfatEntryFileDeleted = 0x05

	// Atributos, compartidos con FAT.
	exfatAttrDirectory = 0x10

	// Caracteres por entrada de nombre.
	exfatCharsPerNameEntry = 15

	maxExfatEntriesPorDir = 1 << 20
)

// exfatParams son los parametros del volumen, ya validados.
type exfatParams struct {
	bytesPerSector    int64
	sectorsPerCluster int64
	clusterSize       int64
	fatOffset         int64
	fatLength         int64
	clusterHeapOffset int64
	clusterCount      uint32
	rootCluster       uint32
}

// parseExfatBoot lee y valida la cabecera de arranque de exFAT.
//
// A diferencia de FAT32, los tamanos vienen como EXPONENTES de dos, no como
// valores directos: bytesPerSectorShift = 9 significa 512 bytes. Tratarlos como
// valores directos daria un sector de 9 bytes y todo el recorrido saldria mal.
func parseExfatBoot(src interface {
	ReadAt([]byte, int64) (int, error)
}, volumeSize int64) (*exfatParams, error) {
	boot := make([]byte, 512)
	if n, err := src.ReadAt(boot, 0); n < 512 {
		return nil, fmt.Errorf("no se pudo leer el sector de arranque exFAT: %w", err)
	}

	if string(boot[3:11]) != "EXFAT   " {
		return nil, fmt.Errorf("no es un volumen exFAT")
	}

	bytesPerSectorShift := boot[108]
	sectorsPerClusterShift := boot[109]

	if bytesPerSectorShift < 9 || bytesPerSectorShift > 12 {
		return nil, fmt.Errorf("exponente de bytes por sector invalido: %d", bytesPerSectorShift)
	}
	if sectorsPerClusterShift > 25 {
		return nil, fmt.Errorf("exponente de sectores por cluster invalido: %d", sectorsPerClusterShift)
	}

	p := &exfatParams{
		bytesPerSector:    1 << bytesPerSectorShift,
		sectorsPerCluster: 1 << sectorsPerClusterShift,
		clusterCount:      binary.LittleEndian.Uint32(boot[92:96]),
		rootCluster:       binary.LittleEndian.Uint32(boot[96:100]),
	}
	p.clusterSize = p.bytesPerSector * p.sectorsPerCluster

	p.fatOffset = int64(binary.LittleEndian.Uint32(boot[80:84])) * p.bytesPerSector
	p.fatLength = int64(binary.LittleEndian.Uint32(boot[84:88])) * p.bytesPerSector
	p.clusterHeapOffset = int64(binary.LittleEndian.Uint32(boot[88:92])) * p.bytesPerSector

	if p.rootCluster < 2 {
		return nil, fmt.Errorf("cluster raiz invalido: %d", p.rootCluster)
	}
	if p.clusterHeapOffset <= 0 || p.clusterHeapOffset >= volumeSize {
		return nil, fmt.Errorf("el area de datos (offset %d) cae fuera del volumen (%d bytes)",
			p.clusterHeapOffset, volumeSize)
	}
	if p.fatOffset <= 0 || p.fatOffset >= volumeSize {
		return nil, fmt.Errorf("la FAT (offset %d) cae fuera del volumen", p.fatOffset)
	}

	return p, nil
}

// offsetDeCluster traduce un numero de cluster a offset absoluto.
func (p *exfatParams) offsetDeCluster(cluster uint32) int64 {
	if cluster < 2 {
		return -1
	}
	return p.clusterHeapOffset + int64(cluster-2)*p.clusterSize
}

// listExfat recorre el arbol de directorios de un volumen exFAT.
func (l *Lister) listExfat() ([]FileEntry, error) {
	p, err := parseExfatBoot(l.src, l.size)
	if err != nil {
		return nil, err
	}

	fat := newFATTable(l.src, p.fatOffset, p.fatLength)

	var entries []FileEntry
	visited := make(map[uint32]bool)

	l.walkExfatDir(p.rootCluster, "", p, fat, visited, 0, &entries)
	return entries, nil
}

func (l *Lister) walkExfatDir(
	cluster uint32,
	path string,
	p *exfatParams,
	fat *fatTable,
	visited map[uint32]bool,
	depth int,
	entries *[]FileEntry,
) {
	if depth > maxDirDepth || cluster < 2 || visited[cluster] || len(*entries) >= maxEntries {
		return
	}
	visited[cluster] = true

	dirData := l.readExfatChain(cluster, p, fat)
	if len(dirData) == 0 {
		return
	}

	for i := 0; i+dirEntrySize <= len(dirData) && i/dirEntrySize < maxExfatEntriesPorDir; {
		tipo := dirData[i]

		// 0x00 marca el fin del directorio.
		if tipo == 0x00 {
			break
		}

		// Solo interesan los conjuntos de archivo: 0x85 en uso, 0x05 borrado.
		esArchivo := tipo == exfatEntryFile
		esBorrado := tipo == exfatEntryFileDeleted
		if !esArchivo && !esBorrado {
			i += dirEntrySize
			continue
		}

		fe, consumidos := l.parseExfatFileSet(dirData[i:], p, esBorrado)
		if consumidos <= 0 {
			i += dirEntrySize
			continue
		}
		i += consumidos

		if fe == nil || fe.Name == "" {
			continue
		}

		fullPath := fe.Name
		if path != "" {
			fullPath = path + "/" + fe.Name
		}
		fe.Path = fullPath

		*entries = append(*entries, *fe)

		if fe.IsDir && !fe.IsDeleted && fe.firstCluster >= 2 {
			l.walkExfatDir(fe.firstCluster, fullPath, p, fat, visited, depth+1, entries)
		}
	}
}

// parseExfatFileSet interpreta un conjunto de entradas: la de archivo (0x85),
// la de stream (0xC0) con tamano y primer cluster, y las de nombre (0xC1).
//
// Devuelve la entrada y cuantos bytes consumio, para que el recorrido avance
// sobre el conjunto completo y no reinterprete sus miembros como entradas
// sueltas.
func (l *Lister) parseExfatFileSet(data []byte, p *exfatParams, borrado bool) (*FileEntry, int) {
	if len(data) < dirEntrySize {
		return nil, 0
	}

	// SecondaryCount indica cuantas entradas siguen a la principal.
	secundarias := int(data[1])
	if secundarias < 1 || secundarias > 18 {
		return nil, 0 // conjunto imposible: datos corruptos
	}
	total := (secundarias + 1) * dirEntrySize
	if total > len(data) {
		return nil, 0
	}

	attrs := binary.LittleEndian.Uint16(data[4:6])

	fe := &FileEntry{
		IsDir:     attrs&exfatAttrDirectory != 0,
		IsDeleted: borrado,
		ModTime:   decodeFATTime(binary.LittleEndian.Uint16(data[10:12]), binary.LittleEndian.Uint16(data[12:14])),
	}

	var (
		nombre       strings.Builder
		vistoStream  bool
		noFatChain   bool
		longitudName int
	)

	for k := 1; k <= secundarias; k++ {
		off := k * dirEntrySize
		if off+dirEntrySize > len(data) {
			break
		}
		sub := data[off : off+dirEntrySize]

		// Al borrar, exFAT tambien apaga el bit 0x80 de las entradas
		// secundarias, asi que hay que comparar ignorandolo.
		switch sub[0] | 0x80 {
		case exfatEntryStream:
			vistoStream = true
			// GeneralSecondaryFlags bit 1: NoFatChain. Cuando esta activo los
			// datos son contiguos y no hace falta recorrer la FAT.
			noFatChain = sub[1]&0x02 != 0
			longitudName = int(sub[3])
			fe.firstCluster = binary.LittleEndian.Uint32(sub[20:24])
			fe.Size = int64(binary.LittleEndian.Uint64(sub[8:16]))

		case exfatEntryName:
			// 15 caracteres UTF-16LE por entrada, desde el byte 2.
			for c := 0; c < exfatCharsPerNameEntry; c++ {
				pos := 2 + c*2
				if pos+2 > len(sub) {
					break
				}
				u := binary.LittleEndian.Uint16(sub[pos : pos+2])
				if u == 0 {
					break
				}
				nombre.WriteString(string(utf16.Decode([]uint16{u})))
			}
		}
	}

	if !vistoStream {
		return nil, total
	}

	n := nombre.String()
	// NameLength dice cuantos caracteres son reales; el resto es relleno.
	if longitudName > 0 {
		runas := []rune(n)
		if longitudName < len(runas) {
			n = string(runas[:longitudName])
		}
	}
	fe.Name = strings.TrimSpace(n)

	if fe.firstCluster < 2 {
		return nil, total
	}

	offset := p.offsetDeCluster(fe.firstCluster)
	if offset < 0 || offset >= l.size {
		return nil, total
	}
	fe.Offset = offset

	// Recoverable solo si sabemos que los datos son contiguos. Con NoFatChain
	// activo lo garantiza el propio formato; sin el, harian falta las cadenas de
	// la FAT y un FileEntry con un unico Offset no puede representarlo.
	fe.Recoverable = !fe.IsDir &&
		fe.Size > 0 &&
		noFatChain &&
		offset+fe.Size <= l.size

	return fe, total
}

// readExfatChain concatena los clusters de un directorio.
func (l *Lister) readExfatChain(startCluster uint32, p *exfatParams, fat *fatTable) []byte {
	var data []byte
	cluster := startCluster
	seen := make(map[uint32]bool)

	for i := 0; i < maxClustersPerChain; i++ {
		if cluster < 2 || seen[cluster] {
			break
		}
		seen[cluster] = true

		offset := p.offsetDeCluster(cluster)
		if offset < 0 || offset >= l.size {
			break
		}

		buf := make([]byte, p.clusterSize)
		n, err := l.src.ReadAt(buf, offset)
		if n > 0 {
			data = append(data, buf[:n]...)
		}
		if err != nil && n == 0 {
			break
		}

		next, ok := fat.next(cluster)
		if !ok {
			break
		}
		cluster = next
	}

	return data
}
