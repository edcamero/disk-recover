package filesystem

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"
)

const (
	dirEntrySize = 32

	// maxClustersPerChain acota una cadena individual de clusters.
	maxClustersPerChain = 100000

	// maxDirDepth acota la recursión entre directorios.
	maxDirDepth = 64

	// maxEntries acota el total de entradas devueltas, para que una FAT
	// corrupta no genere resultados sin fin.
	maxEntries = 2000000

	// fatPageSize es el tamaño de página al consultar la FAT bajo demanda.
	fatPageSize = 64 << 10

	attrLongName  = 0x0F
	attrDirectory = 0x10
	attrVolumeID  = 0x08

	entryFree     = 0xE5
	entryEndOfDir = 0x00
)

// bootParams son los parámetros del BPB, ya validados.
type bootParams struct {
	bytesPerSector    int64
	sectorsPerCluster int64
	clusterSize       int64
	fatStart          int64
	fatBytes          int64
	dataStart         int64
	rootCluster       uint32
}

// parseBootSector lee y VALIDA el BPB.
//
// Validar no es opcional aquí: el escenario para el que existe esta herramienta
// es un disco dañado, y el sector de arranque es de lo primero que se corrompe.
// Sin comprobaciones, un bytesPerSector a 0 propaga un clusterSize de 0 y el
// recorrido entero produce basura en silencio, sin un solo error.
func parseBootSector(src interface {
	ReadAt([]byte, int64) (int, error)
}, volumeSize int64) (*bootParams, error) {
	boot := make([]byte, 512)
	if n, err := src.ReadAt(boot, 0); n < 512 {
		return nil, fmt.Errorf("no se pudo leer el sector de arranque: %w", err)
	}

	p := &bootParams{
		bytesPerSector:    int64(binary.LittleEndian.Uint16(boot[11:13])),
		sectorsPerCluster: int64(boot[13]),
		rootCluster:       binary.LittleEndian.Uint32(boot[44:48]),
	}
	reservedSectors := int64(binary.LittleEndian.Uint16(boot[14:16]))
	numFATs := int64(boot[16])
	sectorsPerFAT := int64(binary.LittleEndian.Uint32(boot[36:40]))

	switch p.bytesPerSector {
	case 512, 1024, 2048, 4096:
	default:
		return nil, fmt.Errorf("bytes por sector inválido: %d", p.bytesPerSector)
	}
	if p.sectorsPerCluster <= 0 || p.sectorsPerCluster > 128 ||
		p.sectorsPerCluster&(p.sectorsPerCluster-1) != 0 {
		return nil, fmt.Errorf("sectores por cluster inválido: %d", p.sectorsPerCluster)
	}
	if numFATs < 1 || numFATs > 2 {
		return nil, fmt.Errorf("número de FATs inválido: %d", numFATs)
	}
	if reservedSectors < 1 {
		return nil, fmt.Errorf("sectores reservados inválido: %d", reservedSectors)
	}
	if sectorsPerFAT < 1 {
		return nil, fmt.Errorf("sectores por FAT inválido: %d", sectorsPerFAT)
	}
	if p.rootCluster < 2 {
		return nil, fmt.Errorf("cluster raíz inválido: %d", p.rootCluster)
	}

	p.clusterSize = p.bytesPerSector * p.sectorsPerCluster
	p.fatStart = reservedSectors * p.bytesPerSector
	p.fatBytes = sectorsPerFAT * p.bytesPerSector
	p.dataStart = p.fatStart + numFATs*p.fatBytes

	if p.dataStart <= 0 || p.dataStart >= volumeSize {
		return nil, fmt.Errorf("el área de datos (offset %d) cae fuera del volumen (%d bytes)",
			p.dataStart, volumeSize)
	}

	return p, nil
}

// fatTable consulta la FAT bajo demanda, con una página en caché.
//
// La versión anterior cargaba la FAT entera en memoria de una sola vez. En un
// volumen FAT32 de 2 TB con clusters de 4 KB eso son ~2 GB, y además exigía que
// ReadAt llenara el buffer completo: un único sector defectuoso dentro de la FAT
// abortaba todo el listado, justo lo contrario del objetivo declarado de
// tolerar fallos.
type fatTable struct {
	src interface {
		ReadAt([]byte, int64) (int, error)
	}
	start   int64
	sizeB   int64
	page    []byte
	pageOff int64
	pageLen int
	hasPage bool
}

func newFATTable(src interface {
	ReadAt([]byte, int64) (int, error)
}, start, sizeB int64) *fatTable {
	return &fatTable{src: src, start: start, sizeB: sizeB, page: make([]byte, fatPageSize)}
}

// next devuelve el siguiente cluster de la cadena, o (0, false) si termina o la
// entrada es ilegible.
func (t *fatTable) next(cluster uint32) (uint32, bool) {
	off := int64(cluster) * 4
	if off < 0 || off+4 > t.sizeB {
		return 0, false
	}

	pageOff := off / fatPageSize * fatPageSize
	if !t.hasPage || t.pageOff != pageOff {
		toRead := int64(len(t.page))
		if pageOff+toRead > t.sizeB {
			toRead = t.sizeB - pageOff
		}
		n, err := t.src.ReadAt(t.page[:toRead], t.start+pageOff)
		if n <= 0 && err != nil {
			return 0, false // página ilegible: la cadena se corta aquí
		}
		t.pageOff, t.pageLen, t.hasPage = pageOff, n, true
	}

	rel := int(off - t.pageOff)
	if rel+4 > t.pageLen {
		return 0, false
	}

	nextCluster := binary.LittleEndian.Uint32(t.page[rel:rel+4]) & 0x0FFFFFFF
	if nextCluster < 2 || nextCluster >= 0x0FFFFFF8 {
		return 0, false // libre, reservado o fin de cadena
	}
	return nextCluster, true
}

// listFAT32 recorre una estructura FAT32 tolerando fallos.
func (l *Lister) listFAT32() ([]FileEntry, error) {
	p, err := parseBootSector(l.src, l.size)
	if err != nil {
		return nil, err
	}

	fat := newFATTable(l.src, p.fatStart, p.fatBytes)

	var entries []FileEntry
	// visited se comparte entre TODA la recursión: es lo que impide que un
	// ciclo de directorios (A -> B -> A, trivial en una FAT corrupta) provoque
	// recursión infinita y un desbordamiento de pila irrecuperable.
	visited := make(map[uint32]bool)

	l.walkFAT32Dir(p.rootCluster, "", p, fat, visited, 0, &entries)
	return entries, nil
}

func (l *Lister) walkFAT32Dir(
	cluster uint32,
	path string,
	p *bootParams,
	fat *fatTable,
	visited map[uint32]bool,
	depth int,
	entries *[]FileEntry,
) {
	if depth > maxDirDepth || cluster < 2 || visited[cluster] || len(*entries) >= maxEntries {
		return
	}
	visited[cluster] = true

	dirData := l.readClusterChain(cluster, p, fat)
	if len(dirData) == 0 {
		return
	}

	// Las entradas de nombre largo preceden a su entrada 8.3, en orden inverso.
	// Se van acumulando aquí hasta encontrarla.
	var lfnParts []string

	for i := 0; i+dirEntrySize <= len(dirData); i += dirEntrySize {
		entry := dirData[i : i+dirEntrySize]

		if entry[0] == entryEndOfDir {
			break
		}

		deleted := entry[0] == entryFree
		attr := entry[11]

		// Entrada de nombre largo: acumular y seguir.
		//
		// Se acumulan TAMBIÉN las de archivos borrados. Al borrar, FAT solo
		// sobrescribe el PRIMER byte de cada entrada del archivo con 0xE5; en
		// una entrada LFN ese byte es el número de secuencia, mientras que los
		// caracteres del nombre viven en los bytes 1-10, 14-25 y 28-31 y quedan
		// intactos. Como las entradas LFN preceden a su 8.3 en orden inverso, la
		// posición basta para reensamblar y se recupera el nombre completo.
		//
		// Descartarlas era perder el nombre real de justo los archivos que más
		// interesa recuperar: los borrados.
		if attr&attrLongName == attrLongName {
			lfnParts = append(lfnParts, decodeLFNPart(entry))
			continue
		}

		// Etiqueta de volumen: no es un archivo.
		if attr&attrVolumeID != 0 {
			lfnParts = lfnParts[:0]
			continue
		}

		name := assembleLFN(lfnParts)
		lfnParts = lfnParts[:0]
		if name == "" {
			// Sin nombre largo solo queda el 8.3. Si la entrada está borrada, su
			// primera letra se perdió al marcarla con 0xE5 y no hay forma de
			// recuperarla: se sustituye por '_' en lugar de dejar un byte no
			// imprimible que acabaría saneado a cualquier cosa.
			name = extractFATShortName(entry, deleted)
		}
		if name == "" || name == "." || name == ".." {
			continue
		}

		firstCluster := uint32(binary.LittleEndian.Uint16(entry[20:22]))<<16 |
			uint32(binary.LittleEndian.Uint16(entry[26:28]))

		// Comprobar ANTES de calcular el offset. firstCluster es uint32, así que
		// firstCluster-2 con valor 0 o 1 (frecuente en entradas corruptas) hace
		// underflow a ~4.29e9 y produce un offset astronómico. La versión
		// anterior calculaba el offset primero y comprobaba después, dejando la
		// basura dentro del FileEntry.
		if firstCluster < 2 {
			continue
		}

		isDir := attr&attrDirectory != 0
		fileSize := int64(binary.LittleEndian.Uint32(entry[28:32]))
		offset := p.dataStart + int64(firstCluster-2)*p.clusterSize

		if offset < 0 || offset >= l.size {
			continue // apunta fuera del volumen
		}

		fullPath := name
		if path != "" {
			fullPath = path + "/" + name
		}

		*entries = append(*entries, FileEntry{
			Name:      name,
			Path:      fullPath,
			Offset:    offset,
			Size:      fileSize,
			IsDir:     isDir,
			ModTime:   decodeFATTime(binary.LittleEndian.Uint16(entry[22:24]), binary.LittleEndian.Uint16(entry[24:26])),
			IsDeleted: deleted,
			// Una entrada borrada conserva su primer cluster pero la cadena en
			// la FAT ya está liberada, así que solo es recuperable si los datos
			// siguen siendo contiguos. Se marca y se deja que decida el llamante.
			Recoverable: fileSize > 0 && offset+fileSize <= l.size,
		})

		if isDir && !deleted {
			l.walkFAT32Dir(firstCluster, fullPath, p, fat, visited, depth+1, entries)
		}
	}
}

// readClusterChain concatena los clusters de una cadena, tolerando los que no
// se puedan leer.
func (l *Lister) readClusterChain(startCluster uint32, p *bootParams, fat *fatTable) []byte {
	var data []byte
	cluster := startCluster
	seen := make(map[uint32]bool)

	for i := 0; i < maxClustersPerChain; i++ {
		if cluster < 2 || seen[cluster] {
			break // fin de cadena, o ciclo dentro de la propia cadena
		}
		seen[cluster] = true

		offset := p.dataStart + int64(cluster-2)*p.clusterSize
		if offset < 0 || offset >= l.size {
			break
		}

		buf := make([]byte, p.clusterSize)
		n, err := l.src.ReadAt(buf, offset)
		if n > 0 {
			data = append(data, buf[:n]...)
		}
		if err != nil && n == 0 {
			break // cluster ilegible
		}

		next, ok := fat.next(cluster)
		if !ok {
			break
		}
		cluster = next
	}

	return data
}

// decodeLFNPart extrae los 13 caracteres UTF-16LE de una entrada de nombre
// largo. Van repartidos en tres tramos no contiguos del registro de 32 bytes.
func decodeLFNPart(entry []byte) string {
	units := make([]uint16, 0, 13)
	appendRange := func(from, to int) {
		for i := from; i+1 < to; i += 2 {
			u := binary.LittleEndian.Uint16(entry[i : i+2])
			if u == 0x0000 || u == 0xFFFF {
				return
			}
			units = append(units, u)
		}
	}
	appendRange(1, 11)
	appendRange(14, 26)
	appendRange(28, 32)
	return string(utf16.Decode(units))
}

// assembleLFN une los fragmentos acumulados. Vienen en orden inverso en el
// directorio, así que se recorren de atrás hacia delante.
func assembleLFN(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	var sb strings.Builder
	for i := len(parts) - 1; i >= 0; i-- {
		sb.WriteString(parts[i])
	}
	return strings.TrimSpace(sb.String())
}

func extractFATShortName(entry []byte, deleted bool) string {
	raw := make([]byte, 11)
	copy(raw, entry[0:11])

	// 0x05 en el primer byte codifica un 0xE5 literal (kanji), para no
	// confundirlo con la marca de entrada borrada.
	if raw[0] == 0x05 {
		raw[0] = 0xE5
	}

	// En una entrada borrada el primer carácter del nombre fue sustituido por
	// la marca 0xE5 y es irrecuperable. Se marca con '_' para que el nombre siga
	// siendo legible y quede claro que falta una letra.
	if deleted && raw[0] == entryFree {
		raw[0] = '_'
	}

	name := strings.TrimRight(string(raw[0:8]), " \x00")
	ext := strings.TrimRight(string(raw[8:11]), " \x00")

	name = strings.ToLower(strings.TrimSpace(name))
	ext = strings.ToLower(strings.TrimSpace(ext))

	if name == "" {
		return ""
	}
	if ext != "" {
		return name + "." + ext
	}
	return name
}

func decodeFATTime(timeWord, dateWord uint16) time.Time {
	day := int(dateWord & 0x1F)
	month := int((dateWord >> 5) & 0x0F)
	year := 1980 + int((dateWord>>9)&0x7F)

	// Una fecha corrupta es habitual; devolver el cero de time.Time deja que el
	// llamante la ignore en lugar de propagar un time.Date normalizado absurdo
	// como "31 de febrero" convertido en marzo.
	if month < 1 || month > 12 || day < 1 || day > 31 {
		return time.Time{}
	}

	sec := int(timeWord&0x1F) * 2
	min := int((timeWord >> 5) & 0x3F)
	hour := int((timeWord >> 11) & 0x1F)
	if sec > 59 || min > 59 || hour > 23 {
		return time.Time{}
	}

	return time.Date(year, time.Month(month), day, hour, min, sec, 0, time.Local)
}
