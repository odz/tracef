// $Id: prototype.h,v 1.2 2007/09/16 13:49:58 sato Exp $
#ifndef DWARF_H_
#define DWARF_H_

#include <string>
#include <libdwarf/libdwarf.h>
#include <boost/shared_ptr.hpp>

namespace hoge {
  class elf;

  enum dw_types {
    TYPE_UNKNOWN =  -1,
    TYPE_POINTER,    
    TYPE_INT,        
    TYPE_UINT,       
    TYPE_SHORT,      
    TYPE_USHORT,     
    TYPE_CHAR,       
    TYPE_UCHAR,      
    TYPE_LONG,       
    TYPE_ULONG,      
    TYPE_LONGLONG,   
    TYPE_ULONGLONG,  
    TYPE_SIZE_T,     
    TYPE_OFF_T,      
    TYPE_OFF64_T, 
  };

  int get_debug_info(pid_t pid, elf& psymbols);
  const char* str_dw_types(dw_types t);
}

#endif

