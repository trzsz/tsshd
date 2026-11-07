BIN_DIR := ./bin
BIN_DST := /usr/bin

ifdef GOOS
	ifeq (${GOOS}, windows)
		WIN_TARGET := True
	endif
else
	ifeq (${OS}, Windows_NT)
		WIN_TARGET := True
	endif
endif

ifdef WIN_TARGET
	TSSHD := tsshd.exe
else
	TSSHD := tsshd
endif

ifeq (${OS}, Windows_NT)
	RM := PowerShell -Command Remove-Item -Force
	GO_TEST := go test
	NULL_DEVICE := NUL
else
	RM := rm -f
	GO_TEST := ${shell basename `which gotest 2>/dev/null` 2>/dev/null || echo go test}
	NULL_DEVICE := /dev/null
endif

EXAMPLE_DIRS := $(patsubst %/main.go, %, $(wildcard ./examples/*/main.go))
EXAMPLE_OUT_DIR ?= ../../bin/

.PHONY: all clean test install examples ${EXAMPLE_DIRS}

all: ${BIN_DIR}/${TSSHD}

${BIN_DIR}/${TSSHD}: $(wildcard ./cmd/tsshd/*.go ./tsshd/*.go) go.mod go.sum
	go build -o ${BIN_DIR}/ ./cmd/tsshd

clean:
	$(foreach f, $(wildcard ${BIN_DIR}/*), $(RM) $(f);)

test: EXAMPLE_OUT_DIR := ${NULL_DEVICE}
test: ${EXAMPLE_DIRS}
	${GO_TEST} -v -count=1 ./...

examples: ${EXAMPLE_DIRS}
$(EXAMPLE_DIRS):
	go build -C $@ -o ${EXAMPLE_OUT_DIR}

install: all
ifdef WIN_TARGET
	@echo install target is not supported for Windows
else
	@mkdir -p ${DESTDIR}${BIN_DST}
	cp ${BIN_DIR}/tsshd ${DESTDIR}${BIN_DST}/
endif
