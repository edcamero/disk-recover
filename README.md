# disk-recover

> File carving con clasificación inteligente. Escrito en Go.

[![Go Report Card](https://goreportcard.com/badge/github.com/edcamero/disk-recover)](https://goreportcard.com/report/github.com/edcamero/disk-recover)
[![Go Reference](https://pkg.go.dev/badge/github.com/edcamero/disk-recover.svg)](https://pkg.go.dev/github.com/edcamero/disk-recover)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**TL;DR**: Herramienta CLI y librería Go para recuperar archivos de discos dañados/formateados, con clasificación automática que distingue fotos personales de iconos del sistema.

---

## ¿Por qué otro recuperador?

Existen [PhotoRec](https://www.cgsecurity.org/testdisk.html), [Foremost](https://github.com/korczis/foremost) y [Scalpel](https://github.com/sleuthkit/scalpel). Son excelentes haciendo file carving, pero comparten el mismo problema:

> Recuperan **TODO**: tus fotos de vacaciones mezcladas con 50.000 iconos de Windows, recursos de programas y archivos temporales.

`disk-recover` añade una capa de **clasificación post-carving** que:

- ✅ Detecta fotos personales vía EXIF/XMP (cámara, GPS, fecha)
- ✅ Filtra iconos por resolución (16x16, 32x32, 256x256)
- ✅ Recupera nombres originales cuando es posible
- ✅ Organiza automáticamente en `user_content/`, `system_files/`, `unknown/`

**No reemplaza a PhotoRec** — lo complementa con inteligencia aplicada al problema real del usuario final.

---

## Arquitectura

```
                          ┌──────────────────┐
                          │   CLI (main.go)  │
                          │  -mode, -classify│
                          └────────┬─────────┘
                                   │
                ┌──────────────────┼──────────────────┐
                ▼                                     ▼
        ┌──────────────┐                      ┌──────────────┐
        │ filesystem/  │  (FS legible)        │   carver/    │ (FS destruido)
        │  list.go     │  → nombres, carpetas │   carver.go  │  → firmas mágicas
        │  fat32.go    │                      │              │
        │  ntfs.go     │                      └──────┬───────┘
        └──────┬───────┘                             │
               │                                     │
               └──────────────┬──────────────────────┘
                              ▼
                    ┌──────────────────┐
                    │   scanner/       │  ← lectura eficiente con overlap
                    │   scanner.go     │    (ventana deslizante 1MB+64KB)
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │   signatures/    │  ← registry thread-safe
                    │   registry.go    │    + carga desde archivo .sig
                    │   magic.go (pkg) │    + wildcards (?? bytes)
                    └────────┬─────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
      ┌──────────────┐ ┌──────────┐ ┌──────────────┐
      │ classifier/  │ │namerecov/│ │   output/    │
      │ exif, size,  │ │ EXIF/XMP │ │  SafeWriter  │
      │ resolution   │ │ strings  │ │  atómico+hash│
      └──────────────┘ └──────────┘ └──────────────┘
```

### Separación de responsabilidades

| Paquete | Responsabilidad | Lo que NO hace |
|---|---|---|
| `pkg/magic` | Parseo, matching y detección de bytes mágicos | No lee discos |
| `internal/scanner` | Lectura por bloques con overlap y cancelación | No sabe qué es un JPEG |
| `internal/signatures` | Registro de firmas, carga desde `.sig` | No escanea |
| `internal/carver` | Orquesta scanner + signatures | No clasifica |
| `internal/classifier` | Decide si un archivo es "usuario" o "sistema" | No lee EXIF directamente (usa helpers) |
| `internal/namerecovery` | Intenta recuperar nombres originales | No garantiza 100% |
| `internal/filesystem` | Modo `list`: lee FS parcialmente legible | No hace carving |
| `internal/output` | Escritura atómica, anti-colisión, anti-sobrescritura | No busca archivos |

---

## Estado actual

### Integridad y trazabilidad

| Capacidad | Estado |
|---|---|
| **Validación del contenido**: lo corrupto va a `dudosos/`, no mezclado | ✅ |
| Puntuación de integridad por archivo (0 a 1) | ✅ |
| Manifiesto de auditoría en JSONL, legible aunque se corte la luz | ✅ |
| Reanudar un escaneo interrumpido (`-reanudar`) | ✅ |
| Deduplicación por SHA256, también entre ejecuciones | ✅ |
| Comprobación de espacio libre antes de empezar | ✅ |
| Rechazo de escribir en el disco de origen, incluido `\\.\PhysicalDriveN` | ✅ |

### Recuperación

| Capacidad | Estado |
|---|---|
| File carving por firmas mágicas, con comodines y búsqueda de footer | ✅ |
| Escritura atómica: reserva con `O_EXCL`, `fsync`, SHA256 en streaming | ✅ |
| Clasificación por EXIF, dimensiones y tamaño | ✅ |
| Recuperación de nombres desde EXIF/XMP y barrido del directorio | ✅ |
| Modo `list` sobre **FAT32**, con nombres largos (LFN) | ✅ |
| **Archivos borrados en FAT**: se recupera el nombre largo completo | ✅ |
| Modo `list` sobre **exFAT**: nombres UTF-16, borrados, `NoFatChain` | ✅ |
| Modo `list` sobre NTFS: nombre, tamaño y data runs contiguos | ⚠️ Parcial |
| Archivos NTFS fragmentados (varios data runs) | ❌ Se detectan pero no se extraen |
| Archivos NTFS residentes (contenido dentro de la MFT) | ❌ Pendiente |
| Archivos exFAT sin `NoFatChain` (fragmentados) | ❌ Se detectan pero no se extraen |
| FAT12/FAT16 | ❌ Se detecta y se rechaza explícitamente; usa `-mode=carve` |
| ext4 | ❌ Solo detección |

Lo marcado como pendiente se rechaza de forma explícita en lugar de producir
resultados silenciosamente incorrectos: en una herramienta de recuperación,
devolver basura con aspecto de éxito es peor que no devolver nada.

### Sobre la validación

Un archivo recuperado por carving puede estar **fragmentado**: el carver extrae
cabecera + datos de otro archivo + cola, y el resultado tiene los marcadores
correctos pero el contenido corrupto. Es indetectable mirando solo la forma.

La validación usa dos señales complementarias, porque ninguna basta sola:

| Señal | Relleno de baja entropía | Otro archivo comprimido |
|---|---|---|
| Decodificación completa | **no detecta** | detecta |
| Racha de bytes idénticos | detecta | **no detecta** |

Un relleno sin ningún `0xFF` no rompe el escapado de marcadores del JPEG, así
que el decodificador lee códigos Huffman basura pero válidos y termina sin
error. Por eso hace falta también la heurística de rachas, cuyo umbral se midió
sobre JPEG reales: el techo es 129 sin importar tamaño ni contenido.

PNG usa el CRC32 de cada chunk, que es determinista y no necesita descomprimir.

---

## Quick Start

### Requisitos

- Go 1.22+
- Permisos elevados **solo** si trabajas con dispositivos en crudo (`/dev/sdX`, `\\.\PhysicalDrive0`)

Funciona en Linux, macOS y Windows; el binario es nativo en los tres.

### Windows

Con **imágenes de disco** (`.img`, `.dd`) no hay nada especial que hacer:

```powershell
.\bin\recover.exe -src backup.img -out .\recuperados
```

Para leer un **disco en crudo** hace falta una consola como Administrador y la
ruta de espacio de nombres de Windows:

```powershell
.\bin\recover.exe -src \\.\PhysicalDrive1 -out D:\recuperados -mode=carve
.\bin\recover.exe -src \\.\E: -out D:\recuperados
```

> **`-src D:` no lee el disco.** Una letra de unidad suelta en Windows es la
> *carpeta* de esa unidad, no sus bytes: `ReadAt` sobre ella falla con
> `Incorrect function` y su tamaño es 0. La herramienta lo detecta y traduce
> `D:` a `\\.\D:` automáticamente, avisando de lo que ha hecho, pero conviene
> escribir la ruta correcta desde el principio. Una ruta a un archivo
> (`D:\backup.img`) nunca se toca.

Al detectar una ruta `\\.\`, la herramienta alinea automáticamente las lecturas
al tamaño de sector. Es imprescindible: Windows abre esos dispositivos sin búfer
y exige que **tanto el offset como la longitud** de cada lectura sean múltiplos
del sector. El carver pide los bytes exactos de cada archivo, y un JPEG rara vez
mide un múltiplo de 512, así que sin alinear la última lectura de cada archivo
devolvería `ERROR_INVALID_PARAMETER` y no se recuperaría nada.

Si el disco es 4Kn (sector nativo de 4096 bytes, no emulado):

```powershell
.\bin\recover.exe -src \\.\PhysicalDrive1 -out D:\recuperados -sector 4096
```

**Limitación en Windows**: la comprobación "el destino no está en el disco de
origen" solo funciona con `\\.\X:`, donde se puede comparar la letra de volumen.
Con `\\.\PhysicalDriveN` no hay forma fiable de asociar el disco físico a una
unidad sin consultar los volúmenes del sistema, así que esa protección **no
salta**. Elige el destino con cuidado: nunca en el disco que estás recuperando.

> Como siempre, lo más seguro es trabajar sobre una imagen y no sobre el disco.
> En Windows puedes hacerla con [ddrelease64](http://www.chrysocome.net/dd) o
> con `dd` desde WSL.

### Compilar

```bash
git clone https://github.com/edcamero/disk-recover
cd disk-recover
go build -o bin/disk-recover ./cmd/recover
```

### Uso básico

```bash
# 1. SIEMPRE crea una imagen del disco dañado primero
sudo dd if=/dev/sdb of=backup.img bs=4M conv=noerror,sync status=progress

# 2. Recuperar con modo automático (intenta list, fallback a carve)
./bin/disk-recover -src backup.img -out ./recuperados -user-only

# 3. Forzar solo carving (FS completamente destruido)
./bin/disk-recover -src backup.img -out ./recuperados -mode=carve

# 4. Usar firmas personalizadas
./bin/disk-recover -src backup.img -out ./recuperados -sigfile custom.sig
```

### Flags

```
-src string       Dispositivo o imagen (requerido)
-out string       Directorio de salida (default "./recovered")
-mode string      auto | list | carve (default "auto")
-classify         Activar clasificación inteligente (default true)
-user-only        Eliminar archivos de sistema/iconos
-sigfile string   Archivo de firmas adicional (.sig)
-category string  Filtrar por categoría: image, video, document, archive
-sector int       Tamaño de sector para dispositivos en crudo (default 512)
-reanudar         Continuar un escaneo interrumpido en lugar de empezar de cero
-no-validar       Desactivar la validación profunda (no distingue íntegro de corrupto)
-min-libre int    Espacio libre mínimo exigido en el destino, en bytes (default 1GB)
```

---

## Uso como librería

El proyecto está diseñado para poder importarse como módulo Go:

```go
package main

import (
    "log"
    "os"

    "github.com/edcamero/disk-recover/internal/carver"
    "github.com/edcamero/disk-recover/internal/classifier"
    "github.com/edcamero/disk-recover/internal/output"
    "github.com/edcamero/disk-recover/internal/signatures"
)

func main() {
    f, err := os.Open("backup.img")
    if err != nil {
        log.Fatal(err)
    }
    defer f.Close()

    info, _ := f.Stat()

    // 1. Configurar el registro de firmas
    reg := signatures.DefaultRegistry()
    reg.LoadFromFile("custom.sig") // opcional

    // 2. El escritor decide dónde acaban los archivos. Construirlo aquí es lo
    //    que activa la comprobación "el destino no está en el disco de origen":
    //    si lo está, NewSafeWriter falla y no se escribe nada.
    w, err := output.NewSafeWriter("./out", "backup.img")
    if err != nil {
        log.Fatal(err)
    }

    // 3. Ejecutar el carving
    c := carver.New(f, info.Size(), w, reg)
    results, err := c.Run()
    if err != nil {
        log.Fatal(err)
    }

    // 4. Clasificar
    cls := classifier.New()
    for _, r := range results {
        verdict, err := cls.Classify(r.Path, r.Offset)
        if err == nil && verdict.IsUserContent {
            // procesar foto personal: verdict.Category, verdict.Camera, ...
        }
    }
}
```

> **Ojo con el tamaño en dispositivos de bloque**: `Stat().Size()` devuelve `0`
> para `/dev/sdX` en Linux, porque `st_size` solo tiene sentido en archivos
> regulares. Para un dispositivo hay que usar `f.Seek(0, io.SeekEnd)`. El CLI ya
> lo hace; una integración propia tiene que hacerlo también.

---

## Añadir firmas

### Desde código

```go
reg := signatures.DefaultRegistry()
reg.Register(signatures.Signature{
    Name:      "heic",
    Extension: ".heic",
    Category:  "image",
    // Los 4 primeros bytes son el tamaño del box y varían en cada archivo:
    // "??" los marca como comodín.
    Header:  magic.MustParse("?? ?? ?? ?? 66 74 79 70 68 65 69 63"),
    MaxSize: 50 << 20,
})
```

Los comodines importan más de lo que parece. Recortar una firma hasta su parte
fija produce falsos positivos masivos: la firma de MP4 como `00 00 00` coincide
con cualquier secuencia de tres ceros, y en un disco formateado —lleno de ceros
por definición— eso son millones de coincidencias pidiendo extraer 4 GB cada una.

### Desde archivo `custom.sig`

```
# Formato compatible mentalmente con PhotoRec/Foremost
name: cr2
ext: .cr2
category: image
header: 49 49 2A 00 10 00 00 00 43 52
maxsize: 100MB
---
name: mkv
ext: .mkv
category: video
header: 1A 45 DF A3
maxsize: 10GB
```

Los wildcards (`??`) están soportados vía `pkg/magic`:

```
name: mp4_custom
header: ?? ?? ?? ?? 66 74 79 70
```

---

## Estado actual

### ✅ Funcionando

- [x] File carving con firmas (JPEG, PNG, GIF, WebP, MP4, AVI, PDF, ZIP)
- [x] Lectura eficiente con ventana deslizante (overlap configurable)
- [x] Clasificación por EXIF + tamaño + resolución
- [x] Recuperación de nombres vía EXIF/XMP/string scanning
- [x] Modo `list` para FAT32 y NTFS (parcial)
- [x] Escritura atómica con SHA256 integrado
- [x] Cancelación graceful con `Ctrl+C`
- [x] Protección contra sobrescribir el disco origen

### 🚧 En progreso

- [ ] Parser ext4 completo
- [ ] Reconstrucción de estructura de directorios
- [ ] Soporte para RAW de cámaras (CR3, NEF, ARW, DNG)
- [ ] Interfaz TUI con barra de progreso
- [ ] Paralelización multi-goroutine del carving

### ❌ Fuera de scope (por ahora)

- Recuperación de archivos cifrados (BitLocker, FileVault)
- Análisis forense con cadena de custodia certificada
- Recuperación de SSD con TRIM activado (limitación física)

---

## Limitaciones conocidas (seamos honestos)

1. **Archivos fragmentados**: Si los clusters de un archivo están dispersos, el carving solo recupera el primer fragmento. Esto es inherente al enfoque, no un bug.
2. **Falsos positivos**: Secuencias aleatorias de bytes pueden parecer firmas válidas. El `classifier` mitiga esto, pero no lo elimina.
3. **Archivos sin footer** (MP4, AVI): Se usa heurística de tamaño, que puede fallar.
4. **Nombres originales**: La recuperación depende de metadatos EXIF/XMP o strings cercanos. Si no existen, no hay forma mágica de recuperarlos.
5. **SSDs con TRIM**: Los datos pueden estar físicamente borrados. Ninguna herramienta puede recuperar lo que ya no existe.

---

## Comparativa técnica

| Característica | PhotoRec | Foremost | Scalpel | **disk-recover** |
|---|:---:|:---:|:---:|:---:|
| File carving | ✅ | ✅ | ✅ | ✅ |
| Nº de firmas | ~480 | ~100 | ~100 | ~8 (extensible) |
| Clasificación inteligente | ❌ | ❌ | ❌ | ✅ |
| Filtra iconos del sistema | ❌ | ❌ | ❌ | ✅ |
| Análisis EXIF | ❌ | ❌ | ❌ | ✅ |
| Recuperación de nombres | ⚠️ básico | ❌ | ❌ | ✅ |
| Modo "list" con FS dañado | ❌ | ❌ | ❌ | ✅ |
| Escritura atómica + hash | ❌ | ❌ | ❌ | ✅ |
| Binario único cross-platform | ❌ | ❌ | ❌ | ✅ |
| Lenguaje | C | C | C++ | Go |

---

## Contribuir

PRs bienvenidas. Áreas donde más ayuda se necesita:

1. **Más firmas**: ver `internal/signatures/signatures.go` — el archivo `photorec.sig` de PhotoRec tiene ~480 que podríamos portar.
2. **Parser ext4**: ver `internal/filesystem/ext4.go` — actualmente es un stub.
3. **Tests**: la cobertura es baja, especialmente en `filesystem/` y `namerecovery/`.
4. **Documentación**: godoc comments en funciones exportadas.

### Convenciones

- Commits en español o inglés, pero consistentes
- `go fmt` + `golangci-lint` antes de PR
- Tests obligatorios para funciones públicas nuevas
- Issues en español o inglés

```bash
# Antes de hacer PR
go fmt ./...
go vet ./...
go test ./...
```

---

## Referencias y agradecimientos

Este proyecto bebe de:

- [PhotoRec / TestDisk](https://www.cgsecurity.com/testdisk.html) — la biblia del file carving
- [Foremost](https://github.com/korczis/foremost) — formato de archivo `.conf`
- [The Sleuth Kit](https://github.com/sleuthkit/sleuthkit) — parsers de FS forenses
- [github.com/rwcarlsen/goexif](https://github.com/rwcarlsen/goexif) — parser EXIF en Go
- [Bulk Extractor](https://github.com/simsong/bulk_extractor) — enfoque de extracción sin FS

---

## Licencia

MIT © 2026 — Ver [LICENSE](LICENSE) para detalles.

---

## Disclaimer

Esta herramienta es para **recuperación de datos propios**. El uso para acceder a datos de terceros sin autorización es ilegal en la mayoría de jurisdicciones. No está diseñada para uso forense con cadena de custodia — para eso usa herramientas certificadas como [Autopsy](https://www.autopsy.com/) o [EnCase](https://opentext.com/products/encase-forensic).