%define unmangled_name proton-core
%define version 0.1.7
%define release 1

Prefix: %{_prefix}

Name: python3-%{unmangled_name}
Version: %{version}
Release: %{release}%{?dist}
Summary: %{unmangled_name} library

Group: ProtonVPN
License: GPLv3
Vendor: Proton Technologies AG <opensource@proton.me>
URL: https://github.com/ProtonVPN/%{unmangled_name}
Source0: %{unmangled_name}-%{version}.tar.gz
BuildArch: noarch
BuildRoot: %{_tmppath}/%{unmangled_name}-%{version}-%{release}-buildroot


BuildRequires: python3-bcrypt
BuildRequires: python3-gnupg
BuildRequires: python3-pyOpenSSL
BuildRequires: python3-requests
BuildRequires: python3-aiohttp
BuildRequires: python3-importlib-metadata
BuildRequires: python3-pyotp
BuildRequires: python3-setuptools
Requires: python3-bcrypt
Requires: python3-gnupg
Requires: python3-pyOpenSSL
Requires: python3-requests
Requires: python3-aiohttp
Requires: python3-importlib-metadata
Conflicts: python3-proton-client

%{?python_disable_dependency_generator}

%description
Package %{unmangled_name} library.


%prep
%setup -n %{unmangled_name}-%{version} -n %{unmangled_name}-%{version}

%build
python3 setup.py build

%install
python3 setup.py install --single-version-externally-managed -O1 --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES


%files -f INSTALLED_FILES
%{python3_sitelib}/proton/
%{python3_sitelib}/proton_core-%{version}*.egg-info/
%defattr(-,root,root)

%changelog
* Tue Mar 07 2023 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.1.7
- Hide SSO CLI

* Tue Mar 07 2023 Josep Llaneras <josep.llaneras@proton.ch> 0.1.6
- Fix invalid attribute

* Mon Mar 06 2023 Josep Llaneras <josep.llaneras@proton.ch> 0.1.5
- Do not leak timeout errors when selecting transport

* Fri Mar 03 2023 Josep Llaneras <josep.llaneras@proton.ch> 0.1.4
- Fix alternative routing crash during domain refresh

* Mon Feb 13 2023 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.1.3
- Recursively create product folders

* Thu Feb 09 2023 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.1.2
- Rely on API for username validation

* Wed Feb 08 2023 Josep Llaneras <josep.llaneras@proton.ch> 0.1.1
- Handle aiohttp timeout error

* Fri Jan 20 2023 Josep Llaneras <josep.llaneras@proton.ch> 0.1.0
- Support posting form-encoded data

* Wed Sep 14 2022 Josep Llaneras <josep.llaneras@proton.ch> 0.0.2
- Make Loader.get_all thread safe.

* Wed Jun 1 2022 Xavier Piroux <xavier.piroux@proton.ch> 0.0.1
- First RPM release
