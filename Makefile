VERSION = $(shell cargo metadata --no-deps --format-version=1 | jq -r '.packages[0].version')
SOURCES = $(shell find . -type f -name '*.rs') Cargo.toml Cargo.lock LICENSE totpm.spec totpm.sysusers testutil/Cargo.lock testutil/Cargo.toml Makefile totpm.conf fedora-test/test.sh fedora-test/user-test.sh
RELEASE ?= 1
FEDORA_RELEASE ?= 40
ARCH ?= x86_64

totpm-$(VERSION).tar.gz: $(SOURCES)
	tar \
		--exclude *.tar.gz \
		--exclude .* \
		--exclude target \
		--exclude *.rpm \
		--exclude results_* \
		--transform 's,^\(\.[^/]\+\),totpm-$(VERSION)/\1,' \
		--transform 's,^\.,totpm-$(VERSION),' \
		-czf totpm-$(VERSION).tar.gz .

totpm-$(VERSION)-1.fc$(FEDORA_RELEASE).src.rpm: totpm-$(VERSION).tar.gz
	fedpkg --release f$(FEDORA_RELEASE) srpm --define "release_number $(RELEASE)"

totpm-$(VERSION)-1.fc$(FEDORA_RELEASE).$(ARCH).rpm: totpm-$(VERSION)-1.fc$(FEDORA_RELEASE).src.rpm
	fedpkg --release f$(FEDORA_RELEASE) mockbuild
	cp -a results_totpm/$(VERSION)/1.fc$(FEDORA_RELEASE)/totpm-$(VERSION)-1.fc$(FEDORA_RELEASE).$(ARCH).rpm ./

.PHONY: test
test:
	cargo test --features=dbus-tests,install
	cargo test

clean:
	fedpkg clean
	rm -rf *.rpm
	rm -rf *.tar.gz
	rm -rf results_totpm
	rm -rf target
	rm -rf testutil/target
