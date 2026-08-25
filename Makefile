BINARY := bin/recover
PKGS   := ./...

.PHONY: all build test vet fmt race cover fuzz lint check clean

all: check build

build:
	go build -o $(BINARY) ./cmd/recover

vet:
	go vet $(PKGS)

fmt:
	gofmt -l -w .

test:
	go test $(PKGS)

# El detector de carreras necesita cgo y un compilador de C. Es imprescindible
# en CI: el registro de firmas se consulta desde varias goroutines.
race:
	CGO_ENABLED=1 go test -race $(PKGS)

cover:
	go test -coverprofile=coverage.out $(PKGS)
	go tool cover -func=coverage.out | tail -1

# Los parsers binarios (NTFS, EXIF, dimensiones) consumen estructuras de discos
# corruptos: son los candidatos naturales a fuzzing.
fuzz:
	go test ./internal/filesystem/ -run=XXX -fuzz=FuzzParseExfatFileSet -fuzztime=60s
	go test ./internal/validate/ -run=XXX -fuzz=FuzzValidateJPEG -fuzztime=60s
	go test ./internal/filesystem/ -run=XXX -fuzz=FuzzParseNTFSRecord -fuzztime=60s
	go test ./internal/classifier/ -run=XXX -fuzz=FuzzParseEXIF -fuzztime=60s
	go test ./pkg/magic/ -run=XXX -fuzz=FuzzParse -fuzztime=30s

# Lo que debería pasar antes de cada commit.
check: fmt vet test

# Uso real: SIEMPRE trabaja sobre una imagen, no sobre el disco dañado.
#   sudo dd if=/dev/sdb of=backup.img bs=4M conv=noerror,sync status=progress
#   make build && ./bin/recover -src backup.img -out ./recuperados
#
# El destino NO puede estar en el mismo dispositivo que el origen: la
# herramienta se niega a arrancar si lo detecta.

clean:
	rm -rf bin coverage.out
