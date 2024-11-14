FEDORA_RELEASE ?= $(shell cut -d' ' -f 3 /etc/fedora-release)

.PHONY: srpm
srpm:
	dnf -y install jq cargo fedpkg
	# Pass this on to the "real" makefile
	make FEDORA_RELEASE=$(FEDORA_RELEASE) srpm
	mkdir -p results
	mv totpm-*.src.rpm $(outdir)/
