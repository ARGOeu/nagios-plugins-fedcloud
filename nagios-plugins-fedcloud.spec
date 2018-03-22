# sitelib
%{!?python_sitelib: %global python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")}
%define dir /usr/libexec/argo-monitoring/probes/fedcloud

Summary: Nagios plugins for EGI FedCloud services
Name: nagios-plugins-fedcloud
Version: 0.1.7
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
%{__python} setup.py build

%install
rm -rf $RPM_BUILD_ROOT
%{__python} setup.py install --skip-build --root %{buildroot} --record=INSTALLED_FILES
install --directory ${RPM_BUILD_ROOT}%{dir}
install --mode 755 src/*  ${RPM_BUILD_ROOT}%{dir}
install -d -m 755 %{buildroot}/%{python_sitelib}/nagios_plugins_fedcloud

%if 0%{?el7:1}
rm -f ${RPM_BUILD_ROOT}%{dir}/check_occi_compute_create
%endif

%clean
rm -rf $RPM_BUILD_ROOT

%files -f INSTALLED_FILES
%defattr(-,root,root,-)
%{dir}
%{python_sitelib}/nagios_plugins_fedcloud

%changelog
* Fri Dec 8 2017 Daniel Vrcic <dvrcic@srce.hr> - 0.1.7-1%{?dist}
- graceful clean-up for OCCI compute probe  
* Mon Nov 20 2017 Daniel Vrcic <dvrcic@srce.hr> - 0.1.6-1%{?dist}
- novaprobe: remove hardcoded port check in token suffix
- novaprobe: ARGO-948 Access token parameter should be file
* Wed Aug 30 2017 Daniel Vrcic <dvrcic@srce.hr> - 0.1.5-1%{?dist}
- novaprobe: use of ids insteads of urls for flavors and image by Enol Fernandez
- novaprobe: added support for OIDC tokens by Enol Fernandez
* Thu Apr 6 2017 Emir Imamagic <eimamagi@srce.hr> - 0.1.4-1%{?dist}
- Version bump
* Tue Dec 13 2016 Daniel Vrcic <dvrcic@srce.hr> - 0.1.3-1%{?dist}
- refactored keystone token and cert check code 
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
