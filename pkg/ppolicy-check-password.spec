Summary: Password policy overlay for OpenLDAP.
Name: ppolicy-check-password
Version: 1.2
Release: 0
Group: OpenLDAP servers and related files.
License: OpenLDAP
URL: https://ltb-project.org
Source0: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Requires: openldap-servers = %{version}
Requires: openldap-servers-overlays = %{version}
BuildRequires: openldap-devel = %{version}

%description
A password policy overlay that provides the ability to:
 - Check passwords against cracklib
 - Ensure that specific quantities of characters from particular character sets
   are used in the password
 - Ensure that a certain number of character sets are used in the password.
 - Ensure that the number of consecutive characters used from a character set
   is limited.

This is derived from work by the LDAP Toolbox Project: https://ltd-project.org

%prep
%setup

%build
if [ ! -f %{_topdir}/SPECS/openldap.spec ]; then
  echo "Error: You need to install the openldap-%{version} source RPM before"
  echo "  running this spec file."
  echo "  Could not find %{_topdir}/SPECS/openldap.spec."

  exit 1
fi

compfile="%{_topdir}/BUILD/openldap-%{version}/openldap-%{version}/build-servers/libraries/liblber/assert.o"

if [ ! -f "$compfile" ]; then
  openldap_comp_arch="undef"
else
  bit64=`file "$compfile" | grep -c 64-bit || true`

  if [ $bit64 -ne 0 ]; then
    openldap_comp_arch="x86_64"
  else
    openldap_comp_arch="i386"
  fi
fi

if [ "$openldap_comp_arch" == "undef" ] || [ "$openldap_comp_arch" != "%{_arch}" ]; then
  rpmbuild -bc %{_topdir}/SPECS/openldap.spec
fi
make LDAP_INC_PATH=%{_topdir}/BUILD/openldap-%{version}/openldap-%{version} LIBDIR=${_libdir}

%install
mkdir -p %{buildroot}/etc/openldap
mkdir -p %{buildroot}%{_libdir}/openldap
mkdir -p %{buildroot}/usr/share/doc/%{name}-%{version}

install -m 755  check_password.so %{buildroot}%{_libdir}/openldap
install -m 644  README %{buildroot}/usr/share/doc/%{name}-%{version}
install -m 644  LICENSE %{buildroot}/usr/share/doc/%{name}-%{version}
install -m 644  INSTALL %{buildroot}/usr/share/doc/%{name}-%{version}

cat << EOF > %{buildroot}/etc/openldap/check_password.conf
min_points 3
use_cracklib 1
min_upper 0
min_lower 0
min_digit 0
min_punct 0
max_consecutive_per_class 5
EOF

chmod 640 %{buildroot}/etc/openldap/check_password.conf

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root)
%attr(-,root,ldap) %config(noreplace) /etc/openldap/check_password.conf
%{_libdir}/openldap/check_password.so
%docdir /usr/share/doc/%{name}-%{version}/
/usr/share/doc/%{name}-%{version}/

%pre

%post

%changelog
* Mon Jan 31 2011 Trevor Vaughan <tvaughan@onyxpoint.com> - 1.2-0
- Initial package
