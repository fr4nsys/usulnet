# usulnet - Frontend Build
# Usa Tailwind CLI standalone (sin Node.js/npm)

TAILWIND_VERSION := 3.4.1
TAILWIND_BIN := ./bin/tailwindcss
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

# Detectar plataforma
ifeq ($(UNAME_S),Linux)
    ifeq ($(UNAME_M),x86_64)
        TAILWIND_PLATFORM := linux-x64
    else ifeq ($(UNAME_M),aarch64)
        TAILWIND_PLATFORM := linux-arm64
    endif
else ifeq ($(UNAME_S),Darwin)
    ifeq ($(UNAME_M),x86_64)
        TAILWIND_PLATFORM := macos-x64
    else ifeq ($(UNAME_M),arm64)
        TAILWIND_PLATFORM := macos-arm64
    endif
endif

TAILWIND_URL := https://github.com/tailwindlabs/tailwindcss/releases/download/v$(TAILWIND_VERSION)/tailwindcss-$(TAILWIND_PLATFORM)

.PHONY: all build watch clean install-tailwind

all: build

# Descargar Tailwind CLI si no existe
install-tailwind:
	@if [ ! -f $(TAILWIND_BIN) ]; then \
		echo "Descargando Tailwind CLI v$(TAILWIND_VERSION) para $(TAILWIND_PLATFORM)..."; \
		mkdir -p bin; \
		curl -sLo $(TAILWIND_BIN) $(TAILWIND_URL); \
		chmod +x $(TAILWIND_BIN); \
		echo "Tailwind CLI instalado en $(TAILWIND_BIN)"; \
	fi

# Compilar CSS para producción
build: install-tailwind
	@echo "Compilando CSS..."
	@mkdir -p dist/css
	$(TAILWIND_BIN) -i src/input.css -o dist/css/style.css --minify
	@echo "CSS compilado: dist/css/style.css ($(shell wc -c < dist/css/style.css | tr -d ' ') bytes)"

# Watch mode para desarrollo
watch: install-tailwind
	@mkdir -p dist/css
	$(TAILWIND_BIN) -i src/input.css -o dist/css/style.css --watch

# Limpiar
clean:
	rm -rf dist/css/style.css

# Limpiar todo (incluido binario)
distclean: clean
	rm -rf bin
