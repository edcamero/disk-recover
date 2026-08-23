package filesystem

func (l *Lister) listExt4() ([]FileEntry, error) {
	// Similar a FAT32 pero con inodos y block groups
	// Implementación compleja - usar github.com/g0rbe/go-ext4 en producción
	return nil, nil
}
