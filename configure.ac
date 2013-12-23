AC_INIT(tracef, 0.16)
AC_CONFIG_SRCDIR(src/main.cpp)
AM_INIT_AUTOMAKE

AC_PROG_CC
AC_PROG_CXX

dnl use g++ for configure checks
AC_LANG_CPLUSPLUS

AC_PROG_INSTALL
AC_HEADER_STDC

AC_C_BIGENDIAN
AC_CHECK_SIZEOF(void *)

AC_CHECK_LIB(elf, elf_begin,, [AC_MSG_ERROR([libelf is not found])])
AC_CHECK_LIB(dwarf, dwarf_def_macro,, [AC_MSG_ERROR([libdwarf is not found])])
AC_CHECK_LIB(iberty, cplus_demangle,, [AC_MSG_ERROR([libiberty is not found])])
AC_CHECK_LIB(bfd, bfd_openr,, [AC_MSG_ERROR([libbfd is not found])], -liberty)
dnl AC_CHECK_LIB(bfd, bfd_is_target_special_symbol,[AC_DEFINE(HAVE_BFD_IS_TARGET_SPECIAL_SYMBOL,1,"bfd_is_target_special_symbol")],, -liberty)
dnl AC_CHECK_LIB(pthread, pthread_self,, [AC_MSG_ERROR([libpthread is not found])])
AC_HAVE_LIBRARY(boost_program_options,, [AC_MSG_ERROR([libboost is not found])])

AC_CHECK_HEADER(libelf.h,,[AC_MSG_ERROR([libelf.h is not found])])
AC_CHECK_HEADER(libdwarf/libdwarf.h,,[AC_MSG_ERROR([libdwarf.h is not found])])
AC_CHECK_HEADER(libdwarf/dwarf.h,,[AC_MSG_ERROR([dwarf.h is not found])])
AC_CHECK_HEADER(bfd.h,,[AC_MSG_ERROR([bfd.h is not found])])
dnl AC_CHECK_HEADER(pthread.h,,[AC_MSG_ERROR([pthread.h is not found])])
AC_CHECK_HEADER(boost/utility.hpp,,[AC_MSG_ERROR([boost/utility.h is not found])])
AC_CHECK_HEADER(ext/functional,,[AC_MSG_ERROR([ext/functional header is not found])])
AC_CHECK_HEADER(ext/stdio_filebuf.h,[AC_DEFINE(HAVE_EXT_STDIO_FILEBUF,1,"ext/stdio_filebuf.h")],)

AC_CONFIG_HEADER(config.h)
AC_OUTPUT([Makefile src/Makefile sample/Makefile doc/Makefile])

