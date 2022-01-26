prefix = /usr/local
exec_prefix = $(prefix)
bindir = $(exec_prefix)/bin
BASHCOMPLETIONSDIR = $(exec_prefix)/share/bash-completion/completions
TAB := $(NULL)<tab>$(NULL)


RM = rm -f
INSTALL = install -D

.PHONY: install uninstall  build clean default
default: build
build:
	go build
clean:
	go clean
reinstall: uninstall install
install:
	$(INSTALL) nextmn-upf $(DESTDIR)$(bindir)/nextmn-upf
	$(INSTALL) bash-completion/completions/nextmn-upf $(BASHCOMPLETIONSDIR)/nextmn-upf
	@echo "================================="
	@echo ">> Now run the following command:"
	@echo "\tsource $(BASHCOMPLETIONSDIR)/nextmn-upf"
	@echo "================================="
uninstall:
	$(RM) $(DESTDIR)$(bindir)/nextmn-upf
	$(RM) $(DESTDIR)$(BASHCOMPLETIONSDIR)/nextmn-upf
