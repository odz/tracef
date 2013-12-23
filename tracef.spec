Summary: function call tracer
Name: tracef
Version: 0.16
Release: 1
License: GPL3
Group: Development/Debuggers
URL: http://d.hatena.ne.jp/yupo5656/
Source0: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
BuildPreReq: gcc-c++ >= 3.4.0
BuildPreReq: libstdc++-devel binutils elfutils-libelf-devel boost-devel
# binutils-devel
# libdwarf
Requires: libstdc++ elfutils-libelf boost

%description

%prep
%setup -q -n %{name}-%{version}

%build
#CXXFLAGS="-fstack-protector --param=ssp-buffer-size=4 -Wp,-D_FORTIFY_SOURCE=2" \
#LDFLAGS="-Wl,-z,relro -Wl,-z,now"  
./configure
cd src
make
cd ..

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/usr/bin
cd src
cp tracef $RPM_BUILD_ROOT/usr/bin
cd ..

%clean
rm -rf $RPM_BUILD_ROOT

%files
/usr/bin/tracef
%defattr(-,root,root,-)
%doc

%post

%changelog
* Mon Sep 17 2007 SATO Yusuke <ads01002 at nifty.com>
- Initial build

