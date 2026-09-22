#!/usr/bin/env bash
# Runs in a fresh target distribution with the package directory mounted read-only.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
case "$PACKAGE_FORMAT" in
    deb)
        apt-get update
        apt-get install -y --no-install-recommends /packages/*.deb
        test "$(dpkg-query -W -f='${Status}' netom)" = 'install ok installed'
        test "$(dpkg-query -W -f='${Architecture}' netom)" = "$PACKAGE_ARCH"
        ;;
    rpm)
        dnf install -y /packages/*.rpm
        test "$(rpm -q --qf '%{ARCH}' netom)" = "$RPM_ARCH"
        ;;
    *) exit 1 ;;
esac

test "$(netom --version)" = "netom $NETOM_VERSION"
test "$(netom-cli --version)" = "netom-cli $NETOM_VERSION"
netom --help > /dev/null
netom-cli --help > /dev/null
user_id=$(id -u netom)
test -f /etc/netom/netom.conf.example
test -f /lib/systemd/system/netom.service || test -f /usr/lib/systemd/system/netom.service
test -f /usr/share/netom/clickhouse/schema.sql
# Reinstall must preserve operator edits and the service account.
printf '\n# packaging preservation test\n' >> /etc/netom/netom.conf.example
case "$PACKAGE_FORMAT" in
    deb) apt-get install -y --reinstall -o Dpkg::Options::=--force-confold /packages/*.deb ;;
    rpm) dnf reinstall -y /packages/*.rpm ;;
esac
grep -q '^# packaging preservation test$' /etc/netom/netom.conf.example
test "$(id -u netom)" = "$user_id"
case "$PACKAGE_FORMAT" in
    deb) apt-get purge -y netom ;;
    rpm) dnf remove -y netom ;;
esac
hash -r
if command -v netom || command -v netom-cli; then
    echo 'Package binaries remain after removal' >&2
    exit 1
fi
