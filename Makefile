VERSION=$(shell cargo metadata --no-deps --format-version=1 | jq -r '.packages[0].version')
SOURCES=$(shell find . -type f -name '*.rs') Cargo.toml Cargo.lock LICENSE totpm.spec totpm.sysusers testutil/Cargo.lock testutil/Cargo.toml Makefile totpm.conf

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

totpm-$(VERSION)-1.fc40.src.rpm: totpm-$(VERSION).tar.gz
	fedpkg --release f40 mockbuild

.PHONY: test
test:
	cargo test --features=dbus-tests,install
	cargo test

clean:
	rm -r *.rpm
	rm -r *.tar.gz
	rm -r totpm_results
	rm -r target
	rm -r testutil/target