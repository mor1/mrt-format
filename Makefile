ORG = mor1
REPO = mrt-format

.PHONY: build
build:
	jbuilder build --dev

.PHONY: clean
clean:
	jbuilder clean

.PHONY: test
test:
	jbuilder runtest --dev

.PHONY: install
install:
	jbuilder build @install
	jbuilder install

.PHONY: uninstall
uninstall:
	jbuilder uninstall

.PHONY: distrib
distrib:
	[ -x $$(opam config var root)/plugins/opam-publish/repos/$(REPO) ] || \
	  opam-publish repo add $(REPO) $(ORG)/$(REPO)
	topkg tag
	topkg distrib

.PHONY: public
publish:
	topkg publish
	topkg opam pkg
	topkg opam submit

.PHONY: release
release: distrib publish
