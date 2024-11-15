VERSION = $(shell cargo metadata --no-deps --format-version=1 | jq -r '.packages[0].version')
SOURCES = $(shell find . -type f -name '*.rs') Cargo.toml Cargo.lock LICENSE totpm.spec totpm.sysusers testutil/Cargo.lock testutil/Cargo.toml Makefile totpm.conf
FEDORA_RELEASE ?= 41
ARCH ?= x86_64

totpm-$(VERSION).tar.gz: $(SOURCES)
	git archive --prefix=totpm-$(VERSION)/ HEAD | gzip > totpm-$(VERSION).tar.gz

totpm-$(VERSION)-1.fc$(FEDORA_RELEASE).src.rpm: totpm-$(VERSION).tar.gz
	fedpkg --release f$(FEDORA_RELEASE) srpm

totpm-$(VERSION)-1.fc$(FEDORA_RELEASE).$(ARCH).rpm: totpm-$(VERSION)-1.fc$(FEDORA_RELEASE).src.rpm fedora-builder/Dockerfile fedora-builder/storage.conf
	podman build \
		-t totpm-builder:$(FEDORA_RELEASE) \
		--build-arg FEDORA_RELEASE=$(FEDORA_RELEASE) \
		fedora-builder

	podman run \
		--privileged \
		-v .:/build:rw,z \
		totpm-builder:$(FEDORA_RELEASE) \
		fedpkg --release f$(FEDORA_RELEASE) mockbuild

	cp -a results_totpm/$(VERSION)/1.fc$(FEDORA_RELEASE)/totpm-$(VERSION)-1.fc$(FEDORA_RELEASE).$(ARCH).rpm ./

.PHONY: fedora-package
fedora-package: totpm-$(VERSION)-1.fc$(FEDORA_RELEASE).$(ARCH).rpm

.PHONY: srpm
srpm: totpm-$(VERSION)-1.fc$(FEDORA_RELEASE).src.rpm

.PHONY: version
version:
	echo $(VERSION)

.PHONY: test
test:
	cargo test --features=dbus-tests,install
	cargo test

.PHONY: fedora-test
fedora-test: totpm-$(VERSION)-1.fc$(FEDORA_RELEASE).$(ARCH).rpm fedora-test/test.sh fedora-test/user-test.sh
	podman pull fedora:$(FEDORA_RELEASE)
	podman run -v ./fedora-test/test.sh:/test.sh:ro,z \
			   -v ./fedora-test/user-test.sh:/user-test.sh:ro,z \
			   -v ./totpm-$(VERSION)-1.fc$(FEDORA_RELEASE).$(ARCH).rpm:/totpm.rpm:ro,z \
			   fedora:$(FEDORA_RELEASE) \
			   bash /test.sh

clean:
	fedpkg clean
	rm -rf *.rpm
	rm -rf *.tar.gz
	rm -rf results_totpm
	rm -rf target
	rm -rf testutil/target
