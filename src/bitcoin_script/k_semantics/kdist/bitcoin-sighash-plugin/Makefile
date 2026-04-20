# Minimal Makefile for bitcoin-sighash-plugin. Produces bitcoin_sighash.a,
# a static library of Bitcoin-specific sighash streaming hooks that gets
# linked into the K LLVM backend interpreter alongside blockchain-k-plugin.
#
# Inputs:
#   K_INCLUDE        : K framework include root. Default from `llvm-kompile`.
#   OPENSSL_PREFIX   : OpenSSL dev root (for <openssl/sha.h>).
#
# Build output:
#   build/bitcoin_sighash.a

PREFIX ?= $(CURDIR)/build
K_INCLUDE ?= $(shell llvm-kompile --include-dir)

OPENSSL_INCLUDE := $(if $(OPENSSL_PREFIX),-I$(OPENSSL_PREFIX)/include,)
GMP_INCLUDE := $(if $(GMP_PREFIX),-I$(GMP_PREFIX)/include,)
MPFR_INCLUDE := $(if $(MPFR_PREFIX),-I$(MPFR_PREFIX)/include,)

CXX ?= c++
CXXFLAGS ?= -O3 -std=c++20 -fPIC -Wall -Wno-unknown-pragmas -Wno-deprecated-declarations

INCLUDES := -I$(K_INCLUDE)/kllvm -I$(K_INCLUDE) \
  $(OPENSSL_INCLUDE) $(GMP_INCLUDE) $(MPFR_INCLUDE)

SRCS := c/bitcoin_sighash.cpp
OBJS := $(patsubst %.cpp,$(PREFIX)/%.o,$(SRCS))

.PHONY: all
all: $(PREFIX)/bitcoin_sighash.a

$(PREFIX)/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c -o $@ $<

$(PREFIX)/bitcoin_sighash.a: $(OBJS)
	@mkdir -p $(dir $@)
	ar rcs $@ $^

.PHONY: clean
clean:
	rm -rf $(PREFIX)
