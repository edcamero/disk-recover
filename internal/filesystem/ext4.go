package filesystem

import (
	"encoding/binary"
	"fmt"
	"time"
)

// Listado de ext4 con recuperación de inodos borrados.
//
// Hay dos pasadas:
//  1. Recorrido de directorios desde el inodo raíz — encuentra archivos activos.
//  2. Barrido de bitmaps de inodos — encuentra inodos con i_dtime != 0 cuyo bit
//     en el bitmap ya fue liberado (O(num_inodos) lecturas; esperado en recovery).
//
// Limitaciones deliberadas:
//   - Sin bloques indirectos (ext2/ext3 legacy): ext4 siempre usa extents.
//   - Sin htree (hash-tree directories): se leen como lineales; funciona igual.
//   - Sin inline data: archivos < 60 bytes en el inodo mismo; el carver los cubre.

const (
	ext4Magic        = 0xEF53
	ext4SuperOff     = 1024
	ext4RootIno      = 2
	ext4ExtentsMagic = uint16(0xF30A)
	ext4ExtentsFL    = uint32(0x00080000) // i_flags: usa árbol de extents

	ext4ModeFmt = 0xF000
	ext4ModeDir = 0x4000
	ext4ModeReg = 0x8000

	ext4FtDir = 2 // file_type de entrada de directorio

	maxExt4DirData = 64 << 20 // cap para datos de directorio en RAM
	maxExt4Extents = 1024
)

type ext4Params struct {
	blockSize      int64
	inodeSize      int64
	inodesPerGroup int64
	groupCount     int64 // número de grupos de bloques
	firstIno       uint32 // primer inodo no reservado (s_first_ino, típicamente 11)
	bgdtOff        int64 // offset en disco de la tabla de descriptores de grupo
	bgdEntrySize   int64 // bytes por descriptor (32 ó 64 en modo 64-bit)
}

// parseExt4Super lee y valida el superbloque.
func parseExt4Super(src interface {
	ReadAt([]byte, int64) (int, error)
}, volumeSize int64) (*ext4Params, error) {
	sb := make([]byte, 1024)
	if n, err := src.ReadAt(sb, ext4SuperOff); n < 1024 {
		return nil, fmt.Errorf("superbloque ext4 ilegible: %w", err)
	}
	if binary.LittleEndian.Uint16(sb[0x38:0x3A]) != ext4Magic {
		return nil, fmt.Errorf("no es un volumen ext4")
	}

	logBlock := binary.LittleEndian.Uint32(sb[0x18:0x1C])
	if logBlock > 16 {
		return nil, fmt.Errorf("exponente de bloque inválido: %d", logBlock)
	}

	inodesCount := int64(binary.LittleEndian.Uint32(sb[0x00:0x04]))
	p := &ext4Params{
		blockSize:      int64(1024) << logBlock,
		inodeSize:      int64(binary.LittleEndian.Uint16(sb[0x58:0x5A])),
		inodesPerGroup: int64(binary.LittleEndian.Uint32(sb[0x28:0x2C])),
		firstIno:       binary.LittleEndian.Uint32(sb[0x54:0x58]),
	}
	if p.inodeSize < 128 || p.inodesPerGroup <= 0 {
		return nil, fmt.Errorf("parámetros de inodo inválidos: size=%d ipg=%d",
			p.inodeSize, p.inodesPerGroup)
	}
	if p.firstIno == 0 {
		p.firstIno = 11
	}
	p.groupCount = (inodesCount + p.inodesPerGroup - 1) / p.inodesPerGroup
	if p.groupCount > 200000 { // ~3 billones de inodos: supera cualquier disco real
		p.groupCount = 200000
	}

	// s_feature_incompat bit 0x80 = 64-bit mode → usar s_desc_size (offset 0xFE)
	if binary.LittleEndian.Uint32(sb[0x60:0x64])&0x80 != 0 {
		p.bgdEntrySize = int64(binary.LittleEndian.Uint16(sb[0xFE:0x100]))
		if p.bgdEntrySize < 32 {
			p.bgdEntrySize = 32
		}
	} else {
		p.bgdEntrySize = 32
	}

	// La BGDT está en el bloque siguiente a s_first_data_block.
	firstDataBlock := int64(binary.LittleEndian.Uint32(sb[0x14:0x18]))
	p.bgdtOff = (firstDataBlock + 1) * p.blockSize
	if p.bgdtOff <= 0 || p.bgdtOff >= volumeSize {
		return nil, fmt.Errorf("BGDT fuera del volumen (offset %d)", p.bgdtOff)
	}
	return p, nil
}

// ext4ReadInode devuelve los bytes del inodo, o nil si hay error.
func (l *Lister) ext4ReadInode(ino uint32, p *ext4Params) []byte {
	group := int64(ino-1) / p.inodesPerGroup
	local := int64(ino-1) % p.inodesPerGroup

	bgd := make([]byte, p.bgdEntrySize)
	if n, _ := l.src.ReadAt(bgd, p.bgdtOff+group*p.bgdEntrySize); n < 12 {
		return nil
	}
	itBlock := int64(binary.LittleEndian.Uint32(bgd[8:12]))
	inodeOff := itBlock*p.blockSize + local*p.inodeSize
	if inodeOff <= 0 || inodeOff+p.inodeSize > l.size {
		return nil
	}
	inode := make([]byte, p.inodeSize)
	if n, _ := l.src.ReadAt(inode, inodeOff); n < 128 {
		return nil
	}
	return inode
}

// ext4ExtentTree extrae los extents desde un nodo del árbol (inline o en bloque).
func (l *Lister) ext4ExtentTree(node []byte, p *ext4Params, depth int) []Extent {
	if depth > maxDirDepth || len(node) < 12 {
		return nil
	}
	if binary.LittleEndian.Uint16(node[0:2]) != ext4ExtentsMagic {
		return nil
	}
	nEntries := int(binary.LittleEndian.Uint16(node[2:4]))
	nodeDepth := int(binary.LittleEndian.Uint16(node[6:8]))
	if nEntries <= 0 || nEntries > 340 {
		return nil
	}

	var exts []Extent
	if nodeDepth == 0 {
		// Nodo hoja: cada entrada de 12 bytes describe un rango contiguo.
		for i := 0; i < nEntries && len(exts) < maxExt4Extents; i++ {
			e := node[12+i*12:]
			if len(e) < 12 {
				break
			}
			eeLen := int64(binary.LittleEndian.Uint16(e[4:6]))
			if eeLen > 32768 {
				eeLen -= 32768 // fragmento no inicializado
			}
			startHi := int64(binary.LittleEndian.Uint16(e[6:8]))
			startLo := int64(binary.LittleEndian.Uint32(e[8:12]))
			diskOff := ((startHi << 32) | startLo) * p.blockSize
			diskSize := eeLen * p.blockSize
			if diskOff <= 0 || diskOff >= l.size || diskSize <= 0 {
				continue
			}
			if diskOff+diskSize > l.size {
				diskSize = l.size - diskOff
			}
			exts = append(exts, Extent{Offset: diskOff, Size: diskSize})
		}
	} else {
		// Nodo índice: cada entrada apunta a un bloque de nivel inferior.
		for i := 0; i < nEntries && len(exts) < maxExt4Extents; i++ {
			e := node[12+i*12:]
			if len(e) < 12 {
				break
			}
			leafLo := int64(binary.LittleEndian.Uint32(e[4:8]))
			leafHi := int64(binary.LittleEndian.Uint16(e[8:10]))
			childOff := ((leafHi << 32) | leafLo) * p.blockSize
			if childOff <= 0 || childOff+p.blockSize > l.size {
				continue
			}
			child := make([]byte, p.blockSize)
			if n, _ := l.src.ReadAt(child, childOff); n < 12 {
				continue
			}
			exts = append(exts, l.ext4ExtentTree(child, p, depth+1)...)
		}
	}
	return exts
}

// ext4InodeExtents devuelve los extents de un inodo con árbol de extents.
func (l *Lister) ext4InodeExtents(inode []byte, p *ext4Params) []Extent {
	if len(inode) < 0x28+12 {
		return nil
	}
	return l.ext4ExtentTree(inode[0x28:], p, 0)
}

// ext4ReadDirBlocks concatena los bloques de datos de un directorio.
func (l *Lister) ext4ReadDirBlocks(inode []byte, p *ext4Params) []byte {
	flags := binary.LittleEndian.Uint32(inode[0x20:0x24])

	var offsets []int64
	if flags&ext4ExtentsFL != 0 {
		for _, ext := range l.ext4InodeExtents(inode, p) {
			for off := ext.Offset; off < ext.Offset+ext.Size && off+p.blockSize <= l.size; off += p.blockSize {
				offsets = append(offsets, off)
			}
		}
	} else {
		for i := 0; i < 12; i++ {
			block := int64(binary.LittleEndian.Uint32(inode[0x28+i*4 : 0x28+i*4+4]))
			if block == 0 {
				break
			}
			offsets = append(offsets, block*p.blockSize)
		}
	}

	var data []byte
	for _, off := range offsets {
		if int64(len(data)) >= maxExt4DirData {
			break
		}
		buf := make([]byte, p.blockSize)
		n, _ := l.src.ReadAt(buf, off)
		data = append(data, buf[:n]...)
	}
	return data
}

// listExt4 recorre el árbol de directorios y busca inodos borrados.
func (l *Lister) listExt4() ([]FileEntry, error) {
	p, err := parseExt4Super(l.src, l.size)
	if err != nil {
		return nil, err
	}
	var entries []FileEntry
	visited := make(map[uint32]bool)
	l.walkExt4Dir(ext4RootIno, "", p, visited, 0, &entries)
	l.ext4ScanDeletedInodes(p, &entries)
	return entries, nil
}

// ext4ScanDeletedInodes recorre los bitmaps de inodos de todos los grupos y
// reporta los inodos libres (bit=0) que tienen i_dtime != 0 como borrados.
//
// ponytail: O(num_inodos) lecturas — esperado en herramientas de recovery;
// maxEntries acota la salida si el disco tiene millones de archivos borrados.
func (l *Lister) ext4ScanDeletedInodes(p *ext4Params, entries *[]FileEntry) {
	inode := make([]byte, p.inodeSize) // reutilizado para cada inodo
	ibmap := make([]byte, p.blockSize)  // reutilizado para cada grupo

	for g := int64(0); g < p.groupCount && len(*entries) < maxEntries; g++ {
		bgd := make([]byte, p.bgdEntrySize)
		if n, _ := l.src.ReadAt(bgd, p.bgdtOff+g*p.bgdEntrySize); n < 12 {
			continue
		}
		itBlock := int64(binary.LittleEndian.Uint32(bgd[8:12]))
		ibmapBlock := int64(binary.LittleEndian.Uint32(bgd[4:8]))

		ibmapOff := ibmapBlock * p.blockSize
		if ibmapOff <= 0 || ibmapOff+p.blockSize > l.size {
			continue
		}
		if n, _ := l.src.ReadAt(ibmap, ibmapOff); n == 0 {
			continue
		}

		for i := int64(0); i < p.inodesPerGroup && len(*entries) < maxEntries; i++ {
			if (ibmap[i/8]>>(uint(i)%8))&1 == 1 {
				continue // inodo en uso: lo cubre el recorrido de directorios
			}
			ino := uint32(g*p.inodesPerGroup + i + 1)
			if ino < p.firstIno {
				continue // inodo reservado del sistema
			}
			inodeOff := itBlock*p.blockSize + i*p.inodeSize
			if inodeOff <= 0 || inodeOff+p.inodeSize > l.size {
				continue
			}
			if n, _ := l.src.ReadAt(inode, inodeOff); n < 128 {
				continue
			}

			mode := binary.LittleEndian.Uint16(inode[0:2])
			dtime := binary.LittleEndian.Uint32(inode[0x14:0x18])
			if mode&ext4ModeFmt != ext4ModeReg || dtime == 0 {
				continue
			}

			sizeLo := int64(binary.LittleEndian.Uint32(inode[0x04:0x08]))
			sizeHi := int64(binary.LittleEndian.Uint32(inode[0x6C:0x70]))
			size := (sizeHi << 32) | sizeLo
			if size <= 0 {
				continue
			}

			mtime := binary.LittleEndian.Uint32(inode[0x10:0x14])
			flags := binary.LittleEndian.Uint32(inode[0x20:0x24])

			var offset int64
			var extents []Extent
			var recoverable bool

			if flags&ext4ExtentsFL != 0 {
				all := l.ext4InodeExtents(inode, p)
				switch len(all) {
				case 1:
					offset = all[0].Offset
					recoverable = offset+size <= l.size
				default:
					if len(all) > 1 {
						offset = all[0].Offset
						extents = all
						recoverable = true
					}
				}
			} else {
				block := int64(binary.LittleEndian.Uint32(inode[0x28:0x2C]))
				if block > 0 {
					offset = block * p.blockSize
					recoverable = offset+size <= l.size
				}
			}

			name := ext4GuessExt(ino, offset, l)
			*entries = append(*entries, FileEntry{
				Name:        name,
				Path:        name,
				Offset:      offset,
				Size:        size,
				ModTime:     time.Unix(int64(mtime), 0),
				IsDeleted:   true,
				Recoverable: recoverable,
				Extents:     extents,
			})
		}
	}
}

// ext4GuessExt asigna un nombre sintético detectando el tipo por magic bytes.
// Sin esto el usuario no sabe qué tipo de archivo es: un JPEG y un PDF tienen
// el mismo tamaño y mtime, pero solo el nombre da la pista de formato.
func ext4GuessExt(ino uint32, offset int64, l *Lister) string {
	if offset > 0 {
		hdr := make([]byte, 8)
		if n, _ := l.src.ReadAt(hdr, offset); n >= 4 {
			switch {
			case hdr[0] == 0xFF && hdr[1] == 0xD8 && hdr[2] == 0xFF:
				return fmt.Sprintf("$%d.jpg", ino)
			case hdr[0] == 0x89 && hdr[1] == 0x50 && hdr[2] == 0x4E && hdr[3] == 0x47:
				return fmt.Sprintf("$%d.png", ino)
			case hdr[0] == 0x25 && hdr[1] == 0x50 && hdr[2] == 0x44 && hdr[3] == 0x46:
				return fmt.Sprintf("$%d.pdf", ino)
			case hdr[0] == 0x50 && hdr[1] == 0x4B && hdr[2] == 0x03:
				return fmt.Sprintf("$%d.zip", ino)
			case hdr[0] == 0x47 && hdr[1] == 0x49 && hdr[2] == 0x46:
				return fmt.Sprintf("$%d.gif", ino)
			}
		}
	}
	return fmt.Sprintf("$%d.bin", ino)
}

func (l *Lister) walkExt4Dir(ino uint32, path string, p *ext4Params, visited map[uint32]bool, depth int, entries *[]FileEntry) {
	if depth > maxDirDepth || visited[ino] || len(*entries) >= maxEntries {
		return
	}
	visited[ino] = true

	inode := l.ext4ReadInode(ino, p)
	if inode == nil || binary.LittleEndian.Uint16(inode[0:2])&ext4ModeFmt != ext4ModeDir {
		return
	}

	dirData := l.ext4ReadDirBlocks(inode, p)
	pos, count := 0, 0
	for pos+8 <= len(dirData) && count < maxEntries {
		count++
		entIno := binary.LittleEndian.Uint32(dirData[pos : pos+4])
		recLen := int(binary.LittleEndian.Uint16(dirData[pos+4 : pos+6]))
		nameLen := int(dirData[pos+6])
		fileType := dirData[pos+7]

		if recLen < 8 || pos+recLen > len(dirData) {
			break
		}
		if entIno == 0 || nameLen == 0 || pos+8+nameLen > len(dirData) {
			pos += recLen
			continue
		}

		name := string(dirData[pos+8 : pos+8+nameLen])
		if name == "." || name == ".." {
			pos += recLen
			continue
		}

		fullPath := name
		if path != "" {
			fullPath = path + "/" + name
		}

		if fileType == ext4FtDir {
			l.walkExt4Dir(entIno, fullPath, p, visited, depth+1, entries)
		} else if fe := l.ext4FileEntry(entIno, name, fullPath, p); fe != nil {
			*entries = append(*entries, *fe)
		}
		pos += recLen
	}
}

// ext4FileEntry construye un FileEntry para un inodo de archivo regular.
func (l *Lister) ext4FileEntry(ino uint32, name, fullPath string, p *ext4Params) *FileEntry {
	inode := l.ext4ReadInode(ino, p)
	if inode == nil || len(inode) < 128 {
		return nil
	}
	if binary.LittleEndian.Uint16(inode[0:2])&ext4ModeFmt != ext4ModeReg {
		return nil
	}

	sizeLo := int64(binary.LittleEndian.Uint32(inode[0x04:0x08]))
	sizeHi := int64(binary.LittleEndian.Uint32(inode[0x6C:0x70]))
	size := (sizeHi << 32) | sizeLo
	mtime := binary.LittleEndian.Uint32(inode[0x10:0x14])
	dtime := binary.LittleEndian.Uint32(inode[0x14:0x18])
	links := binary.LittleEndian.Uint16(inode[0x1A:0x1C])
	isDeleted := dtime != 0 || links == 0
	flags := binary.LittleEndian.Uint32(inode[0x20:0x24])

	var offset int64
	var extents []Extent
	var recoverable bool

	if flags&ext4ExtentsFL != 0 {
		all := l.ext4InodeExtents(inode, p)
		switch len(all) {
		case 1:
			offset = all[0].Offset
			recoverable = size > 0 && offset+size <= l.size
		default:
			if len(all) > 1 {
				offset = all[0].Offset
				extents = all
				recoverable = size > 0
			}
		}
	} else {
		block := int64(binary.LittleEndian.Uint32(inode[0x28:0x2C]))
		if block > 0 {
			offset = block * p.blockSize
			recoverable = size > 0 && offset+size <= l.size
		}
	}

	return &FileEntry{
		Name:        name,
		Path:        fullPath,
		Offset:      offset,
		Size:        size,
		ModTime:     time.Unix(int64(mtime), 0),
		IsDeleted:   isDeleted,
		Recoverable: recoverable,
		Extents:     extents,
	}
}
