%define unmangled_name proton-core
%define pep_625_name proton_core
%define version 0.7.0
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
Source0: %{pep_625_name}-%{version}.tar.gz
BuildArch: noarch
BuildRoot: %{_tmppath}/%{pep_625_name}-%{version}-%{release}-buildroot


BuildRequires: python3-devel
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
%setup -q -n %{pep_625_name}-%{version}

%build
%pyproject_wheel

%install
%pyproject_install
%pyproject_save_files proton 

%check
%pyproject_check_import

%files -n %{name} -f %{pyproject_files}

%changelog
* Wed Sep 10 2025 Luke Titley <luke.titley@proton.ch> 0.7.0
- Add fido2 support for 2fa authorization.

* Tue Jun 17 2025 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.6.0
- Ensure CI passed soc tests.

* Wed Jun 4 2025 Luke Titley <luke.titley@proton.ch> 0.5.0
- Provide access to the binary response when requesting with 'return_raw'.

* Tue Nov 19 2024 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.4.0
- Require python >= 3.9 to allow libraries using newer language features

* Wed Sep 18 2024 Josep Llaneras <josep.llaneras@proton.ch> 0.3.3
- Amend type hinting

* Wed Sep 11 2024 Xavier Piroux <xavier.piroux@proton.ch> 0.3.2
- ProtonSSO : allow selecting the keyring backend (unspecified: load default keyring)
- External contribution from 'wesinator' : fix hostname segment regex

* Fri Aug 30 2024 Luke Titley <luke.titley@proton.ch> 0.3.1
- Minor changes following feedback/review

* Tue Aug 27 2024 Luke Titley <luke.titley@proton.ch> 0.3.0
- Allow clients to support 'If-Modified-Since'

* Fri Aug 02 2024 Josep Llaneras <josep.llaneras@proton.ch> 0.2.1
- Make logs less verbose

* Mon May 27 2024 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.2.0
- Add dynamic module validation

* Thu May 23 2024 Josep Llaneras <josep.llaneras@proton.ch> 0.1.19
- Sanitize DNS response

* Tue Apr 30 2024 Josep Llaneras <josep.llaneras@proton.ch> 0.1.18
- Fix invalid modulus error when logging in

* Fri Mar 01 2024 Robin Delcros <robin.delcros@proton.ch> 0.1.17
- Session forking

* Thu Nov 16 2023 Laurent Fasnacht <laurent.fasnacht@proton.ch> 0.1.16
- fixing (another) race condition in async_refresh()

* Tue Oct 24 2023 Xavier Piroux <xavier.piroux@proton.ch> 0.1.15
- fixing race condition in async_refresh()

* Tue Oct 24 2023 Josep Llaneras <josep.llaneras@proton.ch> 0.1.14
- Fix crash on Python 3.12

* Thu Oct 19 2023 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.1.13
- Amend setup.py
- Add minimum required python version

* Thu Jul 13 2023 Xavier Piroux <xavier.piroux@proton.ch> 0.1.12
- async_api_request() : raise Exception instead of return None in case of error

* Fri May 12 2023 Xavier Piroux <xavier.piroux@proton.ch> 0.1.11
- API URL : https://vpn-api.proton.me
- fixed Alternative Routing : support IP addresses

* Wed Apr 19 2023 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.1.10
- Add license

* Thu Apr 06 2023 Xavier Piroux <xavier.piroux@proton.ch> 0.1.9
- proton-sso: fixing 2fa

* Mon Mar 27 2023 Josep Llaneras <josep.llaneras@proton.ch> 0.1.8
- Allow running proton.sso module

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
