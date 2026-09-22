Name:           netom
Version:        %{netom_version}
Release:        1
Summary:        Composable, programmable BGP engine
License:        MPL-2.0
URL:            https://github.com/FastNetMon/netom
Requires(pre):  shadow-utils
Requires(pre):  /usr/bin/getent

# Keep Cargo's profiling symbols, as in the DEB; do not split a debuginfo RPM.
%global debug_package %{nil}
%global __strip /bin/true

%description
FastNetMon's BGP/BMP routing data engine, including the netom-cli operational
client. Supports route monitoring, collection, and redistribution.

%install
install -Dm755 %{_sourcedir}/target/release/netom %{buildroot}%{_bindir}/netom
install -Dm755 %{_sourcedir}/target/release/netom-cli %{buildroot}%{_bindir}/netom-cli
install -Dm644 %{_sourcedir}/pkg/common/netom.netom.service %{buildroot}/usr/lib/systemd/system/netom.service
install -Dm644 %{_sourcedir}/etc/netom.conf %{buildroot}%{_sysconfdir}/netom/netom.conf.example
install -Dm644 %{_sourcedir}/etc/examples/filters.roto.example %{buildroot}%{_datadir}/netom/examples/filters.roto.example
install -Dm644 %{_sourcedir}/docs/clickhouse/schema.sql %{buildroot}%{_datadir}/netom/clickhouse/schema.sql
for name in netom netom-cli; do
    install -Dm644 %{_sourcedir}/doc/$name.1 %{buildroot}%{_mandir}/man1/$name.1
done
mkdir -p %{buildroot}%{_docdir}/netom/clickhouse %{buildroot}%{_licensedir}/netom %{buildroot}/var/lib/netom
cp %{_sourcedir}/LICENSE %{buildroot}%{_licensedir}/netom/
cp %{_sourcedir}/README.md %{_sourcedir}/NOTICE.md %{_sourcedir}/docs/bmp-tcp-in.md %{_sourcedir}/docs/clickhouse.md %{buildroot}%{_docdir}/netom/
cp %{_sourcedir}/docs/clickhouse/schema.sql %{_sourcedir}/docs/clickhouse/example.conf %{buildroot}%{_docdir}/netom/clickhouse/

%pre
getent group netom >/dev/null || groupadd --system netom
getent passwd netom >/dev/null || useradd --system --gid netom --home-dir /var/lib/netom --no-create-home --shell /sbin/nologin netom

%post
if [ -d /run/systemd/system ] && [ -x /usr/bin/systemctl ]; then
    /usr/bin/systemctl daemon-reload || :
fi

%preun
if [ "$1" -eq 0 ] && [ -d /run/systemd/system ] && [ -x /usr/bin/systemctl ]; then
    /usr/bin/systemctl --no-reload disable --now netom.service || :
fi

%postun
if [ -d /run/systemd/system ] && [ -x /usr/bin/systemctl ]; then
    /usr/bin/systemctl daemon-reload || :
    if [ "$1" -ge 1 ]; then
        /usr/bin/systemctl try-restart netom.service || :
    fi
fi

%files
%{_bindir}/netom
%{_bindir}/netom-cli
/usr/lib/systemd/system/netom.service
%dir %{_sysconfdir}/netom
%config(noreplace) %{_sysconfdir}/netom/netom.conf.example
%{_datadir}/netom
%{_mandir}/man1/netom.1*
%{_mandir}/man1/netom-cli.1*
%doc %{_docdir}/netom
%license %{_licensedir}/netom
%dir %attr(0750,netom,netom) /var/lib/netom
