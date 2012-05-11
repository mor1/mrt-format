.PHONY: all clean install build
all: build

NAME=mrt

export OCAMLRUNPARAM=b

setup.ml: _oasis
	oasis setup

setup.bin: setup.ml
	ocamlopt.opt -o $@ $< || ocamlopt -o $@ $< || ocamlc -o $@ $<
	$(RM) setup.cmx setup.cmi setup.o setup.cmo

setup.data: setup.bin
	./setup.bin -configure --override ocamlbuildflags -classic-display

setup: setup.data

build: setup.data $(wildcard lib/*.ml)
	./setup.bin -build

doc: setup.data setup.bin
	./setup.bin -doc

install: build
	./setup.bin -install

test-build: 
	cd lib_test \
	&& ocamlbuild -clean \
	&& ocamlbuild -classic-display -use-ocamlfind omrt.native
test: test-build
	./omrt.native test.mrtd

reinstall: build
	ocamlfind remove $(NAME) || true
	./setup.bin -reinstall

clean:
	ocamlbuild -clean
	$(RM) setup.data setup.log setup.bin

distclean: clean
	$(RM) setup.ml myocamlbuild.ml lib/META lib/*.mllib lib/*.mlpack
	oasis setup-clean