package filesystem

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"
)

// Parseo de NTFS acotado a lo que necesita una herramienta de recuperación:
// nombre, tamaño y dónde están los datos.
//
// Todo lo que entra aquí procede de un volumen dañado, así que cada acceso está
// comprobado. La versión anterior leía data[offset+88] con un offset sacado del
// propio disco y solo comprobaba `offset < len(data)-8`, de modo que un valor
// de 1015 producía un índice 1103 sobre un buffer de 1024: panic garantizado.

const (
	// Tipos de atributo que nos interesan.
	attrFileName = 0x30
	attrData     = 0x80
	attrEnd      = 0xFFFFFFFF

	// Espacios de nombres de $FILE_NAME.
	nsDOS = 2 // nombre 8.3 mutilado: se prefiere cualquier otro

	maxAttrsPerRecord = 64
	minMFTRecordSize  = 512
	maxMFTRecordSize  = 64 << 10
)

// ntfsParams son los parámetros del volumen, ya validados.
type ntfsParams struct {
	bytesPerSector    int64
	sectorsPerCluster int64
	clusterSize       int64
	mftOffset         int64
	recordSize        int64
}

func parseNTFSBoot(src interface {
	ReadAt([]byte, int64) (int, error)
}, volumeSize int64) (*ntfsParams, error) {
	boot := make([]byte, 512)
	if n, err := src.ReadAt(boot, 0); n < 512 {
		return nil, fmt.Errorf("no se pudo leer el sector de arranque NTFS: %w", err)
	}

	p := &ntfsParams{
		bytesPerSector:    int64(binary.LittleEndian.Uint16(boot[11:13])),
		sectorsPerCluster: int64(boot[13]),
	}

	switch p.bytesPerSector {
	case 512, 1024, 2048, 4096:
	default:
		return nil, fmt.Errorf("bytes por sector inválido: %d", p.bytesPerSector)
	}
	if p.sectorsPerCluster <= 0 || p.sectorsPerCluster > 128 {
		return nil, fmt.Errorf("sectores por cluster inválido: %d", p.sectorsPerCluster)
	}
	p.clusterSize = p.bytesPerSector * p.sectorsPerCluster

	mftCluster := int64(binary.LittleEndian.Uint64(boot[48:56]))
	if mftCluster <= 0 {
		return nil, fmt.Errorf("cluster de la MFT inválido: %d", mftCluster)
	}
	p.mftOffset = mftCluster * p.clusterSize
	if p.mftOffset <= 0 || p.mftOffset >= volumeSize {
		return nil, fmt.Errorf("la MFT (offset %d) cae fuera del volumen (%d bytes)",
			p.mftOffset, volumeSize)
	}

	// boot[64] es "clusters por registro MFT", con signo: si es negativo, el
	// tamaño es 2^(-valor) bytes.
	raw := int8(boot[64])
	if raw > 0 {
		p.recordSize = int64(raw) * p.clusterSize
	} else {
		shift := -int(raw)
		if shift < 9 || shift > 16 {
			return nil, fmt.Errorf("tamaño de registro MFT inválido: 2^%d", shift)
		}
		p.recordSize = 1 << shift
	}
	if p.recordSize < minMFTRecordSize || p.recordSize > maxMFTRecordSize {
		return nil, fmt.Errorf("tamaño de registro MFT fuera de rango: %d", p.recordSize)
	}

	return p, nil
}

func (l *Lister) listNTFS() ([]FileEntry, error) {
	p, err := parseNTFSBoot(l.src, l.size)
	if err != nil {
		return nil, err
	}

	// Acotar por el tamaño real del volumen y no por una constante fija. Antes
	// se iteraba 100.000 veces pasara lo que pasara: sobre una imagen pequeña
	// eso son 100.000 lecturas fallidas antes de terminar.
	maxRecords := (l.size - p.mftOffset) / p.recordSize
	if maxRecords > maxEntries {
		maxRecords = maxEntries
	}

	var entries []FileEntry
	buf := make([]byte, p.recordSize)

	for i := int64(0); i < maxRecords; i++ {
		recordOffset := p.mftOffset + i*p.recordSize

		n, err := l.src.ReadAt(buf, recordOffset)
		if n < int(p.recordSize) {
			if err != nil {
				// Limpiar el buffer: si no, la siguiente iteración reparsearía
				// los restos del registro anterior.
				for j := range buf {
					buf[j] = 0
				}
				continue
			}
		}

		if string(buf[0:4]) != "FILE" {
			continue
		}

		record := make([]byte, len(buf))
		copy(record, buf)
		if !applyFixups(record, p.bytesPerSector) {
			continue
		}

		if entry := l.parseNTFSRecord(record, p); entry != nil {
			entries = append(entries, *entry)
		}

		if l.onProgress != nil && i%1000 == 0 && maxRecords > 0 {
			l.onProgress(float64(i) / float64(maxRecords) * 100)
		}
	}

	return entries, nil
}

// applyFixups deshace el "update sequence array" de NTFS.
//
// NTFS sustituye los dos últimos bytes de cada sector del registro por un
// número de secuencia, y guarda los originales en un array aparte. Sin
// restaurarlos, cualquier campo que caiga en un límite de sector se lee
// corrupto.
func applyFixups(record []byte, bytesPerSector int64) bool {
	if len(record) < 8 {
		return false
	}

	usaOffset := int(binary.LittleEndian.Uint16(record[4:6]))
	usaCount := int(binary.LittleEndian.Uint16(record[6:8]))

	if usaCount < 1 || usaOffset < 0 || usaOffset+usaCount*2 > len(record) {
		return false
	}

	usn := record[usaOffset : usaOffset+2]

	// El primer elemento es el número de secuencia; los siguientes son los
	// bytes originales de cada sector.
	for i := 1; i < usaCount; i++ {
		sectorEnd := i*int(bytesPerSector) - 2
		if sectorEnd < 0 || sectorEnd+2 > len(record) {
			return false
		}
		// El final del sector debe llevar el número de secuencia; si no, el
		// registro está corrupto.
		if record[sectorEnd] != usn[0] || record[sectorEnd+1] != usn[1] {
			return false
		}
		src := usaOffset + i*2
		record[sectorEnd] = record[src]
		record[sectorEnd+1] = record[src+1]
	}

	return true
}

// parseNTFSRecord extrae un FileEntry de un registro de la MFT ya corregido.
func (l *Lister) parseNTFSRecord(record []byte, p *ntfsParams) *FileEntry {
	if len(record) < 24 {
		return nil
	}

	flags := binary.LittleEndian.Uint16(record[22:24])
	isDir := flags&0x02 != 0
	isDeleted := flags&0x01 == 0

	usedSize := int(binary.LittleEndian.Uint32(record[24:28]))
	if usedSize <= 0 || usedSize > len(record) {
		usedSize = len(record)
	}

	offset := int(binary.LittleEndian.Uint16(record[20:22]))
	if offset < 24 || offset >= usedSize {
		return nil
	}

	var (
		name       string
		nameSpace  byte = 0xFF
		dataSize   int64
		dataOff    int64
		contiguous bool
		haveData   bool
		inlineData []byte
		dataAttr   []byte // non-nil cuando hay un $DATA no residente fragmentado
	)

	for i := 0; i < maxAttrsPerRecord && offset+8 <= usedSize; i++ {
		attrType := binary.LittleEndian.Uint32(record[offset : offset+4])
		if attrType == attrEnd {
			break
		}

		attrLen := int(binary.LittleEndian.Uint32(record[offset+4 : offset+8]))
		// Un atributo debe avanzar: sin esto, un attrLen de 0 (o que se
		// desborde al truncarlo, como hacía el uint16 anterior) hace bucle
		// infinito.
		if attrLen < 16 || offset+attrLen > usedSize {
			break
		}

		attr := record[offset : offset+attrLen]

		switch attrType {
		case attrFileName:
			if n, ns, ok := parseFileNameAttr(attr); ok {
				// Preferir el nombre largo al 8.3 de compatibilidad.
				if nameSpace == 0xFF || (nameSpace == nsDOS && ns != nsDOS) {
					name, nameSpace = n, ns
				}
			}
		case attrData:
			// Solo el $DATA sin nombre es el contenido del archivo; los
			// nombrados son Alternate Data Streams.
			if attr[9] == 0 {
				if size, off, contig, ok := parseDataAttr(attr, p); ok {
					dataSize, dataOff, contiguous, haveData = size, off, contig, true
					if off == 0 && size > 0 {
						inlineData = residentContent(attr)
					} else if !contig {
						dataAttr = attr // para leer la run list completa después
					}
				}
			}
		}

		offset += attrLen
	}

	if name == "" || !haveData {
		return nil
	}

	// Fragmentado: recorrer la run list completa para obtener todos los extents.
	var dataExtents []Extent
	if !contiguous && dataOff > 0 && dataAttr != nil {
		dataExtents = ntfsRunListExtents(dataAttr, p, l.size)
	}

	// Recoverable si los datos son contiguos, residentes, o fragmentados con extents válidos.
	recoverable := !isDir && dataSize > 0 && (inlineData != nil ||
		(dataOff > 0 && contiguous && dataOff+dataSize <= l.size) ||
		len(dataExtents) > 0)

	return &FileEntry{
		Name:        name,
		Path:        name, // NTFS exige seguir las referencias al padre para la ruta completa
		Offset:      dataOff,
		Size:        dataSize,
		IsDir:       isDir,
		IsDeleted:   isDeleted,
		Recoverable: recoverable,
		Data:        inlineData,
		Extents:     dataExtents,
	}
}

// parseFileNameAttr extrae el nombre de un atributo $FILE_NAME residente.
func parseFileNameAttr(attr []byte) (string, byte, bool) {
	if len(attr) < 24 || attr[8] != 0 {
		return "", 0, false // no residente: $FILE_NAME siempre lo es
	}

	valueLen := int(binary.LittleEndian.Uint32(attr[16:20]))
	valueOff := int(binary.LittleEndian.Uint16(attr[20:22]))
	if valueLen < 66 || valueOff < 0 || valueOff+valueLen > len(attr) {
		return "", 0, false
	}

	content := attr[valueOff : valueOff+valueLen]

	// Dentro del contenido: 0x40 longitud del nombre, 0x41 espacio de nombres,
	// 0x42 el nombre en UTF-16LE.
	nameLen := int(content[0x40])
	nameSpace := content[0x41]
	if nameLen <= 0 || 0x42+nameLen*2 > len(content) {
		return "", 0, false
	}

	units := make([]uint16, nameLen)
	for i := 0; i < nameLen; i++ {
		units[i] = binary.LittleEndian.Uint16(content[0x42+i*2 : 0x44+i*2])
	}

	return string(utf16.Decode(units)), nameSpace, true
}

// residentContent devuelve una copia de los bytes del atributo residente.
// Devuelve nil si el atributo está malformado.
func residentContent(attr []byte) []byte {
	if len(attr) < 22 || attr[8] != 0 {
		return nil
	}
	vLen := int(binary.LittleEndian.Uint32(attr[16:20]))
	vOff := int(binary.LittleEndian.Uint16(attr[20:22]))
	if vLen <= 0 || vOff < 16 || vOff+vLen > len(attr) {
		return nil
	}
	out := make([]byte, vLen)
	copy(out, attr[vOff:vOff+vLen])
	return out
}

// parseDataAttr localiza el contenido del archivo.
//
// Devuelve tamaño, offset absoluto en el volumen y si los datos son contiguos.
// Para los archivos pequeños NTFS guarda el contenido dentro del propio registro
// de la MFT (residente); ahí offset=0 y el llamante obtiene los bytes con residentContent.
func parseDataAttr(attr []byte, p *ntfsParams) (size, offset int64, contiguous, ok bool) {
	if len(attr) < 16 {
		return 0, 0, false, false
	}

	// Residente: el contenido está dentro del registro MFT. No es extraíble por
	// offset, así que se reporta el tamaño pero no se marca como recuperable.
	if attr[8] == 0 {
		if len(attr) < 20 {
			return 0, 0, false, false
		}
		return int64(binary.LittleEndian.Uint32(attr[16:20])), 0, false, true
	}

	// No residente: el tamaño real está en 0x30 y la runlist en 0x20.
	if len(attr) < 0x40 {
		return 0, 0, false, false
	}
	realSize := int64(binary.LittleEndian.Uint64(attr[0x30:0x38]))
	runOffset := int(binary.LittleEndian.Uint16(attr[0x20:0x22]))
	if realSize < 0 || runOffset < 0x40 || runOffset >= len(attr) {
		return 0, 0, false, false
	}

	firstLCN, runs, ok := parseRunList(attr[runOffset:])
	if !ok || runs == 0 {
		return realSize, 0, false, true
	}

	return realSize, firstLCN * p.clusterSize, runs == 1, true
}

// parseRunList lee la lista de fragmentos y devuelve el LCN del primero y
// cuántos fragmentos hay.
//
// Formato: cada entrada empieza con un byte cuyo nibble bajo es la longitud del
// campo "longitud" y el alto la del campo "offset". Un 0x00 termina la lista.
// El offset es un desplazamiento CON SIGNO relativo al fragmento anterior.
func parseRunList(data []byte) (firstLCN int64, runs int, ok bool) {
	var currentLCN int64
	pos := 0

	for pos < len(data) && runs < 1024 {
		header := data[pos]
		if header == 0x00 {
			break // fin de la lista
		}
		pos++

		lenSize := int(header & 0x0F)
		offSize := int(header >> 4)
		if lenSize == 0 || lenSize > 8 || offSize > 8 {
			return 0, 0, false
		}
		if pos+lenSize+offSize > len(data) {
			return 0, 0, false
		}

		pos += lenSize // la longitud del fragmento no la necesitamos aquí

		if offSize > 0 {
			currentLCN += signedLE(data[pos : pos+offSize])
			pos += offSize
		}
		// offSize == 0 indica un hueco disperso: no aporta LCN.

		if runs == 0 {
			if currentLCN <= 0 {
				return 0, 0, false
			}
			firstLCN = currentLCN
		}
		runs++
	}

	return firstLCN, runs, runs > 0
}

// ntfsRunListExtents convierte todos los fragmentos de una run list NTFS en
// extents de disco. Los huecos dispersos (sparse, offSize == 0) se omiten
// porque no tienen datos físicos en el volumen.
func ntfsRunListExtents(attr []byte, p *ntfsParams, volumeSize int64) []Extent {
	if len(attr) < 0x42 || attr[8] == 0 {
		return nil
	}
	runOff := int(binary.LittleEndian.Uint16(attr[0x20:0x22]))
	if runOff < 0x40 || runOff >= len(attr) {
		return nil
	}
	data := attr[runOff:]

	var exts []Extent
	var currentLCN int64
	pos := 0

	for pos < len(data) && len(exts) < 1024 {
		header := data[pos]
		if header == 0x00 {
			break
		}
		pos++

		lenSize := int(header & 0x0F)
		offSize := int(header >> 4)
		if lenSize == 0 || lenSize > 8 || offSize > 8 {
			break
		}
		if pos+lenSize+offSize > len(data) {
			break
		}

		// Número de clusters del fragmento (sin signo, little-endian).
		var runLen int64
		for i := lenSize - 1; i >= 0; i-- {
			runLen = runLen<<8 | int64(data[pos+i])
		}
		pos += lenSize

		// Desplazamiento del LCN (con signo, relativo al anterior).
		if offSize > 0 {
			currentLCN += signedLE(data[pos : pos+offSize])
			pos += offSize
		}

		if offSize == 0 || currentLCN <= 0 || runLen <= 0 {
			continue // hueco disperso o entrada inválida
		}

		diskOff := currentLCN * p.clusterSize
		diskSize := runLen * p.clusterSize

		if diskOff <= 0 || diskOff >= volumeSize {
			continue
		}
		if diskOff+diskSize > volumeSize {
			diskSize = volumeSize - diskOff
		}

		exts = append(exts, Extent{Offset: diskOff, Size: diskSize})
	}

	return exts
}

// signedLE interpreta hasta 8 bytes little-endian como entero con signo,
// extendiendo el bit de signo del byte más significativo.
func signedLE(b []byte) int64 {
	if len(b) == 0 {
		return 0
	}
	var v int64
	for i := len(b) - 1; i >= 0; i-- {
		v = v<<8 | int64(b[i])
	}
	// Extensión de signo.
	if b[len(b)-1]&0x80 != 0 {
		shift := uint(len(b)) * 8
		if shift < 64 {
			v -= 1 << shift
		}
	}
	return v
}
