prefix = /usr/local
exec_prefix = $(prefix)
bindir = $(exec_prefix)/bin
BASHCOMPLETIONSDIR = $(exec_prefix)/share/bash-completion/completions
SOURCE = bash -c source


RM = rm -f
INSTALL = install -D

.PHONY: install uninstall  build clean default
default: build
build:
	go build
clean:
	go clean
install:
	$(INSTALL) nextmn-upf $(DESTDIR)$(bindir)/nextmn-upf
	$(INSTALL) bash-completion/completions/nextmn-upf $(BASHCOMPLETIONSDIR)/nextmn-upf
	#$(SOURCE) $(BASHCOMPLETIONSDIR)/nextmn-upf
uninstall:
	$(RM) $(DESTDIR)$(bindir)/nextmn-upf
	$(RM) $(DESTDIR)$(BASHCOMPLETIONSDIR)/nextmn-upf
