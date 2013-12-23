// $Id: main.h,v 1.27 2007/09/24 07:57:14 sato Exp $
#ifndef MAIN_H_
#define MAIN_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <map>
#include <string>
#include <sstream>
#include <iostream>
#include <stdexcept>
#include <cerrno>
#include <cstring>
#include <csignal>
#include <unistd.h>
#include <sys/types.h>
#include <boost/shared_ptr.hpp>
#include <boost/static_assert.hpp>

// ILP32 and LP64 are supported. LLP64 is not.
BOOST_STATIC_ASSERT(sizeof(uintptr_t) == sizeof(unsigned long));

typedef unsigned char sinsn_t; // single instruction

#define HT_UNKNOWN_FUNCTION "<UNKNOWN>"
#define HT_UNKNOWN_FILENAME ""

#define HT_NOT_SIGNALED 0
#define HT_SIGNALED     1 
#define HT_DETACH_OK    2 

#define HT_ERR (hoge::std_err)

#define UNUSED_ __attribute__((unused))
#define TLS_    __thread

#define THROW_ERRNO(fn)                         \
  do {                                          \
    hoge::throw_errno(#fn, __FILE__, __LINE__); \
  } while(0)  /* __PRETTY_FUNCTION__ */ 

#define THROW_HEX(msg,num)                                              \
  do {                                                                  \
    std::stringstream ss_;                                              \
    ss_ << (msg)                                                        \
        << ": 0x"                                                       \
        << std::hex                                                     \
        << static_cast<unsigned long long>(num)                         \
        << std::dec                                                     \
        << " (" << __FILE__ << ":" << __LINE__ << ")";                  \
    throw std::runtime_error(ss_.str());                                \
  } while(0)

#define THROW_STR(msg,add)                              \
  do {                                                  \
    std::stringstream ss_;                              \
    ss_ << (msg)                                        \
        << ": " << (add)                                \
        << " (" << __FILE__ << ":" << __LINE__ << ")";  \
    throw std::runtime_error(ss_.str());                \
  } while(0)


// -- Removed. use BOOST_PP_STRINGIZE instead.
// #define HT_XSTR(s) HT_STR(s)
// #define HT_STR(s)  #s 

namespace hoge {
  static std::ostream& std_err = std::cerr;

  extern sig_atomic_t signaled;
  const int signals[] = { SIGINT, SIGTERM }; // internal linkage in C++

  void throw_errno(const char* fn, const char* file, int line);

  namespace detail {
    // _declaration_ of function 'length_of_fn_()' which takes one (namelss)
    // argument 'T (&)[L]', reference to L-elements array of type T, 
    // and returns reference to L-elements _char_ array.
    template<std::size_t L, typename T> 
    char (&lengthof_fn_(T(&)[L]))[L]; /* { static T dummy[L]; return dummy; } */
  }
}
#define HT_LENGTHOF(ary) sizeof(hoge::detail::lengthof_fn_(ary))

#endif
