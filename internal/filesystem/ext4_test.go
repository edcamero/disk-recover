package filesystem

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// buildMinimalExt4 construye una imagen ext4 mínima en memoria.
//
// Layout (bloques de 4 KB):
//
//	Bloque 0  (0-4095)   : espacio de arranque + superbloque en offset 1024
//	Bloque 1  (4096-8191): tabla de descriptores de grupo (BGD, 32 bytes)
//	Bloque 4  (16384-...) : tabla de inodos
//	  inodo 2  (local 1): directorio raíz
//	  inodo 12 (local 11): archivo de prueba
//	Bloque 5  (20480-...) : datos del directorio raíz
//	Bloque 6  (24576-...) : datos del archivo de prueba
func buildMinimalExt4(t *testing.T, filename string, content []byte) []byte {
	t.Helper()
	const (
		blockSize      = 4096
		inodeSize      = 256
		inodesPerGroup = 256
		inodeTableBlock = 4
		dirBlock        = 5
		fileBlock       = 6
		fileIno         = uint32(12)
		totalBlocks     = 7
	)
	disk := make([]byte, totalBlocks*blockSize)

	// ── Superbloque (offset 1024 desde el inicio del disco) ──────────────────
	sb := disk[1024 : 1024+1024]
	binary.LittleEndian.PutUint32(sb[0x00:], 512)                          // s_inodes_count
	binary.LittleEndian.PutUint32(sb[0x04:], uint32(totalBlocks))          // s_blocks_count_lo
	binary.LittleEndian.PutUint32(sb[0x14:], 0)                            // s_first_data_block (0 para bs>1024)
	binary.LittleEndian.PutUint32(sb[0x18:], 2)                            // s_log_block_size (1024<<2=4096)
	binary.LittleEndian.PutUint32(sb[0x20:], 32768)                        // s_blocks_per_group
	binary.LittleEndian.PutUint32(sb[0x28:], inodesPerGroup)               // s_inodes_per_group
	binary.LittleEndian.PutUint16(sb[0x38:], ext4Magic)                    // s_magic
	binary.LittleEndian.PutUint32(sb[0x54:], 11)                           // s_first_ino
	binary.LittleEndian.PutUint16(sb[0x58:], inodeSize)                    // s_inode_size
	// s_feature_incompat = 0: no 64-bit mode → bgdEntrySize = 32
	// s_feature_incompat |= EXT4_FEATURE_INCOMPAT_EXTENTS (0x40) para marcar extents
	binary.LittleEndian.PutUint32(sb[0x60:], 0x40) // s_feature_incompat: extents

	// ── BGD (bloque 1 = offset 4096) ─────────────────────────────────────────
	// Un solo grupo, 32 bytes.
	bgd := disk[1*blockSize : 1*blockSize+32]
	binary.LittleEndian.PutUint32(bgd[0x08:], inodeTableBlock) // bg_inode_table_lo

	// ── Inodo 2: directorio raíz ──────────────────────────────────────────────
	// local = (2-1) % 256 = 1 → offset = inodeTableBlock*4096 + 1*256
	rootInodeOff := inodeTableBlock*blockSize + 1*inodeSize
	ri := disk[rootInodeOff : rootInodeOff+inodeSize]
	binary.LittleEndian.PutUint16(ri[0x00:], 0x41ED) // i_mode: dir + rwxr-xr-x
	binary.LittleEndian.PutUint32(ri[0x04:], blockSize) // i_size_lo
	binary.LittleEndian.PutUint16(ri[0x1A:], 2)          // i_links_count
	binary.LittleEndian.PutUint32(ri[0x20:], uint32(ext4ExtentsFL)) // i_flags
	// Árbol de extents inline en i_block (offset 0x28):
	extHdr := ri[0x28:]
	binary.LittleEndian.PutUint16(extHdr[0x00:], uint16(ext4ExtentsMagic)) // eh_magic
	binary.LittleEndian.PutUint16(extHdr[0x02:], 1)                        // eh_entries
	binary.LittleEndian.PutUint16(extHdr[0x04:], 4)                        // eh_max
	binary.LittleEndian.PutUint16(extHdr[0x06:], 0)                        // eh_depth (leaf)
	// Leaf extent (12 bytes) en offset 12 del header:
	leaf := extHdr[12:]
	binary.LittleEndian.PutUint32(leaf[0x00:], 0)         // ee_block (VCN 0)
	binary.LittleEndian.PutUint16(leaf[0x04:], 1)         // ee_len (1 bloque)
	binary.LittleEndian.PutUint16(leaf[0x06:], 0)         // ee_start_hi
	binary.LittleEndian.PutUint32(leaf[0x08:], dirBlock)  // ee_start_lo

	// ── Inodo de archivo (fileIno = 12): local = 11 ───────────────────────────
	fileInodeOff := inodeTableBlock*blockSize + 11*inodeSize
	fi := disk[fileInodeOff : fileInodeOff+inodeSize]
	binary.LittleEndian.PutUint16(fi[0x00:], 0x81A4) // i_mode: regular + rw-r--r--
	binary.LittleEndian.PutUint32(fi[0x04:], uint32(len(content))) // i_size_lo
	binary.LittleEndian.PutUint32(fi[0x10:], 1700000000)           // i_mtime
	binary.LittleEndian.PutUint16(fi[0x1A:], 1)                    // i_links_count
	binary.LittleEndian.PutUint32(fi[0x20:], uint32(ext4ExtentsFL))
	fHdr := fi[0x28:]
	binary.LittleEndian.PutUint16(fHdr[0x00:], uint16(ext4ExtentsMagic))
	binary.LittleEndian.PutUint16(fHdr[0x02:], 1)
	binary.LittleEndian.PutUint16(fHdr[0x04:], 4)
	binary.LittleEndian.PutUint16(fHdr[0x06:], 0)
	fLeaf := fHdr[12:]
	binary.LittleEndian.PutUint32(fLeaf[0x00:], 0)
	binary.LittleEndian.PutUint16(fLeaf[0x04:], 1)
	binary.LittleEndian.PutUint16(fLeaf[0x06:], 0)
	binary.LittleEndian.PutUint32(fLeaf[0x08:], fileBlock)

	// ── Directorio raíz (bloque dirBlock) ────────────────────────────────────
	dir := disk[dirBlock*blockSize : (dirBlock+1)*blockSize]
	writeExt4DirEntry(dir, 0, 2, ".", 2, 12)
	writeExt4DirEntry(dir, 12, 2, "..", 2, 12)
	nameLen := len(filename)
	entrySize := 8 + nameLen
	if entrySize%4 != 0 {
		entrySize += 4 - entrySize%4
	}
	writeExt4DirEntry(dir, 24, fileIno, filename, 1, blockSize-24)

	// ── Datos del archivo ─────────────────────────────────────────────────────
	copy(disk[fileBlock*blockSize:], content)

	_ = entrySize // suprime warning si nameLen no se usa en otra ruta
	return disk
}

// writeExt4DirEntry escribe una entrada de directorio en buf[pos].
func writeExt4DirEntry(buf []byte, pos int, ino uint32, name string, ftype byte, recLen int) {
	binary.LittleEndian.PutUint32(buf[pos:], ino)
	binary.LittleEndian.PutUint16(buf[pos+4:], uint16(recLen))
	buf[pos+6] = byte(len(name))
	buf[pos+7] = ftype
	copy(buf[pos+8:], name)
}

// TestExt4BasicListing verifica que listExt4 encuentra el archivo con nombre
// y tamaño correctos en una imagen sintética mínima.
func TestExt4BasicListing(t *testing.T) {
	const filename = "hola.txt"
	content := []byte("hola mundo desde ext4\n")

	disk := buildMinimalExt4(t, filename, content)
	l := &Lister{src: bytes.NewReader(disk), size: int64(len(disk))}
	l.fsType = "ext4"

	entries, err := l.listExt4()
	if err != nil {
		t.Fatalf("listExt4: %v", err)
	}

	var found *FileEntry
	for i := range entries {
		if entries[i].Name == filename {
			found = &entries[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("archivo %q no encontrado; entradas: %d", filename, len(entries))
	}
	if found.Size != int64(len(content)) {
		t.Fatalf("Size=%d, se esperaba %d", found.Size, len(content))
	}
	if !found.Recoverable {
		t.Fatal("Recoverable=false para un archivo accesible")
	}
	// El contenido está en el bloque 6 → offset 6*4096 = 24576
	if found.Offset != 6*4096 {
		t.Fatalf("Offset=%d, se esperaba 24576", found.Offset)
	}
}

// TestExt4DeletedInodeRecovery verifica que el barrido de bitmaps encuentra
// un inodo con i_dtime != 0 y lo reporta como borrado con nombre inferido.
func TestExt4DeletedInodeRecovery(t *testing.T) {
	const (
		blockSize       = 4096
		inodeSize       = 256
		inodesPerGroup  = 256
		inodeTableBlock = 4
		ibmapBlock      = 2
		fileBlock       = 6
		totalBlocks     = 7
		// Inode 12 = local index 11 (>= s_first_ino=11, válido para usuario)
		// Bitmap: byte=1 (11/8), bit=3 (11%8)
		deletedIno = uint32(12) // local 11, bit 3 del byte 1
	)
	disk := make([]byte, totalBlocks*blockSize)

	// Superbloque
	sb := disk[1024 : 1024+1024]
	binary.LittleEndian.PutUint32(sb[0x00:], 512)
	binary.LittleEndian.PutUint32(sb[0x04:], totalBlocks)
	binary.LittleEndian.PutUint32(sb[0x18:], 2) // 4096-byte blocks
	binary.LittleEndian.PutUint32(sb[0x20:], 32768)
	binary.LittleEndian.PutUint32(sb[0x28:], inodesPerGroup)
	binary.LittleEndian.PutUint16(sb[0x38:], ext4Magic)
	binary.LittleEndian.PutUint32(sb[0x54:], 11)
	binary.LittleEndian.PutUint16(sb[0x58:], inodeSize)
	binary.LittleEndian.PutUint32(sb[0x60:], 0x40) // extents feature

	// BGD: inode bitmap en bloque 2, inode table en bloque 4
	bgd := disk[1*blockSize : 1*blockSize+32]
	binary.LittleEndian.PutUint32(bgd[0x04:], ibmapBlock)
	binary.LittleEndian.PutUint32(bgd[0x08:], inodeTableBlock)

	// Bitmap: todos los inodos en uso excepto inode 12 (local 11, byte 1 bit 3)
	ibmap := disk[ibmapBlock*blockSize : ibmapBlock*blockSize+blockSize]
	for i := range ibmap {
		ibmap[i] = 0xFF
	}
	ibmap[1] &^= 1 << 3 // local 11 → byte=1, bit=3

	// Inodo 12 (local 11): archivo regular borrado con JPEG magic en bloque 6
	// inodeOff = 4*4096 + 11*256 = 16384 + 2816 = 19200
	fi := disk[19200 : 19200+inodeSize]
	binary.LittleEndian.PutUint16(fi[0x00:], 0x81A4)            // regular file
	binary.LittleEndian.PutUint32(fi[0x04:], 500)               // i_size_lo = 500
	binary.LittleEndian.PutUint32(fi[0x10:], 1700000000)        // i_mtime
	binary.LittleEndian.PutUint32(fi[0x14:], 1700001000)        // i_dtime ← borrado
	binary.LittleEndian.PutUint32(fi[0x20:], uint32(ext4ExtentsFL))
	fHdr := fi[0x28:]
	binary.LittleEndian.PutUint16(fHdr[0x00:], uint16(ext4ExtentsMagic))
	binary.LittleEndian.PutUint16(fHdr[0x02:], 1)
	binary.LittleEndian.PutUint16(fHdr[0x06:], 0) // leaf
	fLeaf := fHdr[12:]
	binary.LittleEndian.PutUint16(fLeaf[0x04:], 1)
	binary.LittleEndian.PutUint32(fLeaf[0x08:], fileBlock)

	// Magic JPEG en el bloque de datos
	disk[fileBlock*blockSize+0] = 0xFF
	disk[fileBlock*blockSize+1] = 0xD8
	disk[fileBlock*blockSize+2] = 0xFF

	l := &Lister{src: bytes.NewReader(disk), size: int64(len(disk))}
	entries, err := l.listExt4()
	if err != nil {
		t.Fatalf("listExt4: %v", err)
	}

	var found *FileEntry
	for i := range entries {
		if entries[i].IsDeleted {
			found = &entries[i]
			break
		}
	}
	if found == nil {
		t.Fatal("no se encontró ningún archivo borrado")
	}
	if found.Size != 500 {
		t.Fatalf("Size=%d, se esperaba 500", found.Size)
	}
	if !found.Recoverable {
		t.Fatal("Recoverable=false para inodo borrado con datos accesibles")
	}
	if found.Offset != fileBlock*blockSize {
		t.Fatalf("Offset=%d, se esperaba %d", found.Offset, fileBlock*blockSize)
	}
	// Magic JPEG → nombre termina en .jpg
	if n := found.Name; len(n) < 4 || n[len(n)-4:] != ".jpg" {
		t.Fatalf("nombre %q no termina en .jpg", found.Name)
	}
}

// TestExt4SuperblockRejectsGarbage verifica que parseExt4Super no hace panic
// con entradas arbitrarias.
func TestExt4SuperblockRejectsGarbage(t *testing.T) {
	cases := [][]byte{
		{},
		make([]byte, 512),
		make([]byte, 2048),
	}
	for _, c := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("panic con input de %d bytes: %v", len(c), r)
				}
			}()
			_, _ = parseExt4Super(bytes.NewReader(c), int64(len(c)))
		}()
	}
}

// FuzzParseExt4Super garantiza que el parser del superbloque no hace panic.
func FuzzParseExt4Super(f *testing.F) {
	f.Add(make([]byte, 7*4096)) // imagen en blanco (falla de validación, no panic)
	f.Add(make([]byte, 4096))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseExt4Super(bytes.NewReader(data), int64(len(data)))
		l := &Lister{src: bytes.NewReader(data), size: int64(len(data))}
		_, _ = l.listExt4()
	})
}
