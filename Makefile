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
else
	RM := rm -f
	GO_TEST := ${shell basename `which gotest 2>/dev/null` 2>/dev/null || echo go test}
endif

.PHONY: all clean test install

all: ${BIN_DIR}/${TSSHD}

${BIN_DIR}/${TSSHD}: $(wildcard ./cmd/tsshd/*.go ./tsshd/*.go) go.mod go.sum
	go build -o ${BIN_DIR}/ ./cmd/tsshd

clean:
	$(foreach f, $(wildcard ${BIN_DIR}/*), $(RM) $(f);)

test:
	${GO_TEST} -v -count=1 ./tsshd

install: all
ifdef WIN_TARGET
	@echo install target is not supported for Windows
else
	@mkdir -p ${DESTDIR}${BIN_DST}
	cp ${BIN_DIR}/tsshd ${DESTDIR}${BIN_DST}/
endif
