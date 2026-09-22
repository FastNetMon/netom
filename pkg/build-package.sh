#!/usr/bin/env bash
set -euo pipefail
format=${1:?Package format required}
version=${2:?Version required}
mkdir -p /out
# ARM hosts can use 4, 16, or 64 KiB pages. A runner's kernel must not decide
# allocator or ELF page-size compatibility for all release consumers.
if [ "$(uname -m)" = aarch64 ]; then
    export JEMALLOC_SYS_WITH_LG_PAGE=16
    export RUSTFLAGS="${RUSTFLAGS:-} -C link-arg=-Wl,-z,max-page-size=65536"
fi
cargo build --locked --release --bin netom --bin netom-cli
# Check the requested version against the actual binaries before packaging.
test "$(target/release/netom --version)" = "netom $version"
test "$(target/release/netom-cli --version)" = "netom-cli $version"
case "$format" in
    deb)
        mkdir -p target/debian
        printf 'netom (%s) unstable; urgency=medium\n\n  * Release %s\n\n -- FastNetMon Inc <support@fastnetmon.com>  %s\n' \
            "$version" "$version" "$(date -R)" > target/debian/changelog
        cargo deb --locked --no-build --output /out/
        ;;
    rpm)
        rpm_version=${version/-/\~}
        rpm_version=${rpm_version//-/.}
        rpmbuild -bb pkg/rpm/netom.spec \
            --define "netom_version $rpm_version" \
            --define "_sourcedir $PWD" \
            --define "_topdir $PWD/target/rpm" \
            --define '_rpmdir /out'
        # rpmbuild puts files in architecture subdirectories.
        mv /out/*/*.rpm /out/
        ;;
    *) echo "Unknown package format: $format" >&2; exit 1 ;;
esac
