PREFIX ?= /usr/local/

target/release: $(wildcard */src/*.rs)
	cargo build --release

# not needed anymore
#workaround:
	#@echo "Applying workaround for https://github.com/bitvecto-rs/bitvec/issues/105" 
	#cargo update -p funty --precise "1.1.0" --verbose

build:
	cargo build

release-build:
	cargo build --release

test:
	cargo test --verbose

clean:
	cargo clean

coverage:
	cargo install grcov
	cargo clean
	export CARGO_INCREMENTAL="0"; \
	export RUSTFLAGS="-Zprofile -Ccodegen-units=1 -Copt-level=0 -Clink-dead-code -Coverflow-checks=off -Zpanic_abort_tests -Cpanic=abort"; \
	export RUSTDOCFLAGS="-Cpanic=abort"; \
	rustup run nightly cargo build -p ethmutator; \
	rustup run nightly cargo test -p ethmutator
	grcov ./target/debug/ -s . -t html --llvm --branch --ignore-not-existing -o ./target/debug/coverage/

install: target/release
	install -D -s -m 755 -t $(PREFIX)/bin/ ./target/release/efuzzcaseanalyzer 
	install -D -s -m 755 -t $(PREFIX)/bin/ ./target/release/efuzzcaseminimizer 
	install -D -s -m 755 -t $(PREFIX)/bin/ ./target/release/efuzzcasetranscoder
	install -D -s -m 755 -t $(PREFIX)/bin/ ./target/release/efuzzcasesynthesizer
	install -D -m 755 -t $(PREFIX)/lib/ ./target/release/libafl_ethmutator.so

uninstall:
	-$(RM) $(PREFIX)/bin/{efuzzcasetranscoder,efuzzcaseminimizer,efuzzcaseanalyzer,efuzzcasesynthesizer}
	-$(RM) $(PREFIX)/lib/libafl_ethmutator.so

.PHONY: build release-build workaround test clean install uninstall
