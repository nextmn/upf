prefix = /usr/local
exec_prefix = $(prefix)
bindir = $(exec_prefix)/bin
BASHCOMPLETIONSDIR = $(exec_prefix)/share/bash-completion/completions


RM = rm -f
INSTALL = install -D

.PHONY: install uninstall update build clean default
default: build
build:
	go build
clean:
	go clean
reinstall: uninstall install
update:
	go get -u github.com/louisroyer/go-pfcp-networking@master
	go mod tidy
install:
	$(INSTALL) upf $(DESTDIR)$(bindir)/upf
	$(INSTALL) bash-completion/completions/upf $(DESTDIR)$(BASHCOMPLETIONSDIR)/upf
	@echo "================================="
	@echo ">> Now run the following command:"
	@echo "\tsource $(DESTDIR)$(BASHCOMPLETIONSDIR)/upf"
	@echo "================================="
uninstall:
	$(RM) $(DESTDIR)$(bindir)/upf
	$(RM) $(DESTDIR)$(BASHCOMPLETIONSDIR)/upf
