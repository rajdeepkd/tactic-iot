# =============================================================================
# Static/dynamic linkage-mix build for the benign worker binaries.
# Build NATIVELY on each board (no cross-compile needed) so the ABI matches the
# capture: armv7l on the RPi 3B+, aarch64 on the RPi 5 and Jetson Nano.
#
# Prerequisites per board (Debian/Raspberry Pi OS / Ubuntu / JetPack):
#   sudo apt-get install -y build-essential musl-tools busybox-static
#   # Go (for the Go twin): apt-get install -y golang  OR  official tarball
#
# Targets:
#   make all        -> build every variant present in the toolchain
#   make c          -> worker-glibc-dynamic + worker-musl-static
#   make go         -> go-worker-dynamic + go-worker-static
#   make manifest   -> write linkage_manifest.csv (verifies balance for the pipeline)
#   make verify     -> print `file` + ldd for each binary (loader-signature check)
#
# The pipeline reads linkage_manifest.csv to assert benign linkage is ~50/50 and
# that the MALWARE sample set (methodology: curated, both linkages) is too --
# otherwise the P7 loader shortcut re-appears.
# =============================================================================

CC        ?= gcc
MUSLCC    ?= musl-gcc
CFLAGS    ?= -O2 -Wall
GO        ?= go
ARCH      := $(shell uname -m)
OUT       := .

.PHONY: all c go manifest verify clean

all: c go manifest

# ---- C twin -----------------------------------------------------------------
c: worker-glibc-dynamic worker-musl-static

worker-glibc-dynamic: worker.c
	$(CC) $(CFLAGS) -o $(OUT)/worker-glibc-dynamic worker.c

# musl static: fully static, no dynamic loader -> different first-k syscalls
worker-musl-static: worker.c
	@if command -v $(MUSLCC) >/dev/null 2>&1; then \
	  $(MUSLCC) $(CFLAGS) -static -o $(OUT)/worker-musl-static worker.c ; \
	else \
	  echo "musl-tools not installed; falling back to glibc -static" ; \
	  $(CC) $(CFLAGS) -static -o $(OUT)/worker-musl-static worker.c ; \
	fi

# ---- Go twin ----------------------------------------------------------------
go: go-worker-static go-worker-dynamic

go-worker-static: worker.go
	CGO_ENABLED=0 $(GO) build -o $(OUT)/go-worker-static worker.go

go-worker-dynamic: worker.go
	CGO_ENABLED=1 $(GO) build -o $(OUT)/go-worker-dynamic worker.go

# ---- linkage manifest (consumed by the assembly pipeline) -------------------
manifest:
	@echo "binary,arch,linkage,toolchain,file_type" > linkage_manifest.csv
	@for b in worker-glibc-dynamic worker-musl-static go-worker-static go-worker-dynamic; do \
	  if [ -x "$$b" ]; then \
	    ft=$$(file -b "$$b" | tr ',' ';') ; \
	    case "$$b" in \
	      *glibc-dynamic) lk=dynamic; tc=glibc ;; \
	      *musl-static)   lk=static;  tc=musl  ;; \
	      go-worker-static)  lk=static;  tc=go ;; \
	      go-worker-dynamic) lk=dynamic; tc=go ;; \
	    esac ; \
	    echo "$$b,$(ARCH),$$lk,$$tc,$$ft" >> linkage_manifest.csv ; \
	  fi ; \
	done
	@cat linkage_manifest.csv

verify:
	@for b in worker-glibc-dynamic worker-musl-static go-worker-static go-worker-dynamic; do \
	  if [ -x "$$b" ]; then echo "== $$b =="; file "$$b"; ldd "$$b" 2>&1 | head -n 3; echo; fi ; \
	done

clean:
	rm -f worker-glibc-dynamic worker-musl-static go-worker-static go-worker-dynamic linkage_manifest.csv
