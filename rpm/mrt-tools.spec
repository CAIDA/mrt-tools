Name:		mrt-tools
Version:	0.1
Release:	1%{?dist}
Summary:	Tools for working with BGP MRT data files

#Group:		
License:	GPL-2.0
URL:		https://github.com/CAIDA/mrt-tools
#Source0:	

#BuildRequires:	
#Requires:	

%description
currently includes bgp-explain

%prep
%{_topdir}/copysource.sh %{_topdir}/.. %{_topdir}/BUILD

%build
#%%configure
make %{?_smp_mflags}

%install
#%make_install
umask 022
mkdir -p %{buildroot}/usr/bin
install -m 0755 src/bgp-explain %{buildroot}/usr/bin/bgp-explain

%files
%defattr(-, root, root)
/usr/bin/bgp-explain
%doc

%changelog
* Sat Mar 1 2025 William Herrin <herrin@caida.org> - 0.1
- initial version

