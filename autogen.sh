#!/bin/sh
# check for your system environment..

(which autoconf) > /dev/null 2>&1  ||
{
    echo "**Error**: You must have autoconf installed to compile tracef."
    echo "Download the appropriate package for your distribution,"
    echo "or get the source at ftp://ftp.gnu.org/pub/gnu/"
    exit 1
}
(which automake) > /dev/null 2>&1  ||
{
    echo "**Error**: You must have automake installed to compile tracef."
    echo "Download the appropriate package for your distribution,"
    echo "or get the source at ftp://ftp.gnu.org/pub/gnu/"
    exit 1
}

#(which libtool) > /dev/null 2>&1  ||
#{
#    echo "**Error**: You must have libtool installed to compile tracef."
#    echo "Download the appropriate package for your distribution,"
#    echo "or get the source at ftp://ftp.gnu.org/pub/gnu/"
#    exit 1
#}
	
# complete missing files..

#(test -f ltconfig) ||
#{
#    (libtoolize --force --copy) ||
#    {
#	echo "**Error**: libtoolize failed."
#	exit 1
#    }
#}


aclocal
autoheader   # create config.h.in
(automake --add-missing) ||
{
    echo "**Error**: automake failed."
    exit 1
}

# generate Makefiles...

automake --foreign
aclocal
autoconf
rm -f config.cache
rm -rf */.deps/*.P

#./configure --enable-debug $* && \
#  echo ; echo "Now type 'make' to build tracef."

