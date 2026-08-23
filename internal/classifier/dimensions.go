package classifier

import "encoding/binary"

// Leer las dimensiones no requiere decodificar la imagen. Todos los formatos que
// nos interesan las llevan en la cabecera, en los primeros bytes: el marcador
// SOF de JPEG, el chunk IHDR de PNG, el logical screen descriptor de GIF. Evitar
// image.Decode ahorra descomprimir megapíxeles por archivo, y además no revienta
// con archivos truncados, que aquí son mayoría.

// readDimensions detecta el formato por sus magic bytes y extrae ancho y alto.
// Devuelve (0, 0, false) si no lo reconoce o la cabecera está incompleta.
func readDimensions(data []byte) (width, height int, ok bool) {
	switch {
	case len(data) >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF:
		return jpegDimensions(data)
	case len(data) >= 8 && string(data[:8]) == "\x89PNG\r\n\x1a\n":
		return pngDimensions(data)
	case len(data) >= 6 && string(data[:4]) == "GIF8":
		return gifDimensions(data)
	case len(data) >= 30 && string(data[:4]) == "RIFF" && string(data[8:12]) == "WEBP":
		return webpDimensions(data)
	case len(data) >= 26 && string(data[:2]) == "BM":
		return bmpDimensions(data)
	}
	return 0, 0, false
}

// jpegDimensions recorre los marcadores hasta encontrar un SOF (Start Of Frame),
// que lleva alto y ancho en claro.
func jpegDimensions(data []byte) (int, int, bool) {
	for pos := 2; pos+4 <= len(data); {
		if data[pos] != 0xFF {
			pos++
			continue
		}

		marker := data[pos+1]

		if marker == 0xD8 || marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7) {
			pos += 2
			continue
		}
		// Empezó el scan comprimido: ya no hay más cabeceras.
		if marker == 0xDA || marker == 0xD9 {
			return 0, 0, false
		}

		segLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		if segLen < 2 || pos+2+segLen > len(data) {
			return 0, 0, false
		}

		// SOF0..SOF15, excluyendo DHT (C4), JPG (C8) y DAC (CC), que comparten rango.
		if marker >= 0xC0 && marker <= 0xCF && marker != 0xC4 && marker != 0xC8 && marker != 0xCC {
			// payload: precisión(1) alto(2) ancho(2)
			if pos+9 > len(data) {
				return 0, 0, false
			}
			h := int(binary.BigEndian.Uint16(data[pos+5 : pos+7]))
			w := int(binary.BigEndian.Uint16(data[pos+7 : pos+9]))
			if w > 0 && h > 0 {
				return w, h, true
			}
			return 0, 0, false
		}

		pos += 2 + segLen
	}
	return 0, 0, false
}

// pngDimensions lee el chunk IHDR, que el estándar obliga a poner el primero.
func pngDimensions(data []byte) (int, int, bool) {
	// 8 firma + 4 longitud + 4 tipo, luego ancho(4) alto(4)
	if len(data) < 24 || string(data[12:16]) != "IHDR" {
		return 0, 0, false
	}
	w := int(binary.BigEndian.Uint32(data[16:20]))
	h := int(binary.BigEndian.Uint32(data[20:24]))
	if w <= 0 || h <= 0 {
		return 0, 0, false
	}
	return w, h, true
}

func gifDimensions(data []byte) (int, int, bool) {
	if len(data) < 10 {
		return 0, 0, false
	}
	w := int(binary.LittleEndian.Uint16(data[6:8]))
	h := int(binary.LittleEndian.Uint16(data[8:10]))
	if w <= 0 || h <= 0 {
		return 0, 0, false
	}
	return w, h, true
}

// webpDimensions cubre las tres variantes del contenedor: VP8 (lossy),
// VP8L (lossless) y VP8X (extendido).
func webpDimensions(data []byte) (int, int, bool) {
	if len(data) < 30 {
		return 0, 0, false
	}
	switch string(data[12:16]) {
	case "VP8 ":
		// Frame header: 3 bytes tag, 3 bytes start code, luego 2+2 dimensiones.
		if len(data) < 30 {
			return 0, 0, false
		}
		w := int(binary.LittleEndian.Uint16(data[26:28]) & 0x3FFF)
		h := int(binary.LittleEndian.Uint16(data[28:30]) & 0x3FFF)
		if w > 0 && h > 0 {
			return w, h, true
		}
	case "VP8L":
		if len(data) < 25 {
			return 0, 0, false
		}
		b := binary.LittleEndian.Uint32(data[21:25])
		w := int(b&0x3FFF) + 1
		h := int((b>>14)&0x3FFF) + 1
		return w, h, true
	case "VP8X":
		if len(data) < 30 {
			return 0, 0, false
		}
		w := int(uint32(data[24])|uint32(data[25])<<8|uint32(data[26])<<16) + 1
		h := int(uint32(data[27])|uint32(data[28])<<8|uint32(data[29])<<16) + 1
		return w, h, true
	}
	return 0, 0, false
}

func bmpDimensions(data []byte) (int, int, bool) {
	if len(data) < 26 {
		return 0, 0, false
	}
	w := int(int32(binary.LittleEndian.Uint32(data[18:22])))
	h := int(int32(binary.LittleEndian.Uint32(data[22:26])))
	if h < 0 {
		h = -h // altura negativa = filas de arriba a abajo
	}
	if w <= 0 || h <= 0 {
		return 0, 0, false
	}
	return w, h, true
}
