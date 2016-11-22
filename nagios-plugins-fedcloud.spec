%define dir /usr/libexec/argo-monitoring/probes/fedcloud

Summary: Nagios plugins for EGI FedCloud services
Name: nagios-plugins-fedcloud
Version: 0.1.1
Release: 1%{?dist}
License: ASL 2.0
Group: Network/Monitoring
Source0: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
BuildArch: noarch
Requires: python >= 2.6
Requires: python-argparse
Requires: python-requests
Requires: pyOpenSSL
%description

%prep
%setup -q

%build

%install
rm -rf $RPM_BUILD_ROOT
install --directory ${RPM_BUILD_ROOT}%{dir}
install --mode 755 src/*  ${RPM_BUILD_ROOT}%{dir}

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%{dir}

%changelog
* Tue Nov 22 2016 Emir Imamagic <eimamagi@srce.hr> - 0.1.1-7%{?dist}
- Probes location aligned with guidelines
* Fri May 13 2016 Daniel Vrcic <dvrcic@srce.hr> - 0.1.0-6%{?dist}
- cdmiprobe: add support for printing error msgs from packed exceptions 
- cdmiprobe: wait some time before next operation
- cdmiprobe: fetched token implies that we have supported CDMI Specification version
- cdmiprobe: merged improvements with proper cleanup procedure by Enol Fernandez
* Tue Jan 19 2016 Daniel Vrcic <dvrcic@srce.hr> - 0.1.0-5%{?dist}
- remove Py2.6 deprecations in cdmiprobe and novaprobe
* Fri Oct 6 2015 Daniel Vrcic <dvrcic@srce.hr> - 0.1.0-4%{?dist}
- novaprobe: debugging helper leftover removed 
* Fri Oct 2 2015 Daniel Vrcic <dvrcic@srce.hr> - 0.1.0-3%{?dist}
- novaprobe: only HTTPS endpoints allowed
* Wed Sep 23 2015 Daniel Vrcic <dvrcic@srce.hr> - 0.1.0-2%{?dist}
- cdmiprobe: handle case when endpoint disabled SSLv3
- novaprobe: added image and flavor cmd options
- novaprobe: no roundtrip, keystone service is given directly
* Fri Sep 18 2015 Emir Imamagic <eimamagi@srce.hr> - 0.1.0-1%{?dist}
- Initial version of EGI FedCloud probes for Nagios
