// $Id: prototype.cpp,v 1.3 2007/09/22 19:35:09 sato Exp $

//
// this code is based on ftrace-0.93.
//
// original code is written by Masanobu Yasui <yasui-m@klab.org> 
//                         and Tsukasa Hamano <hamano@klab.org>.
//
// see http://dsas.blog.klab.org/archives/51043750.html for details.
//

#include "main.h"

#include <map>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <libelf.h>
#include <libdwarf/dwarf.h>

#include "xelf.h"
#include "prototype.h"

#include <algorithm>

namespace {
  using namespace hoge;

  struct type_t {
    off_t offset;
    std::string name;
    std::size_t size;
  };

  int prototype_add_elf(Elf *elf, elf& pelf);
  int prototype_add_cu(Dwarf_Debug dbg, Dwarf_Die die, 
                       elf& pelf);
  int prototype_add(Dwarf_Debug dbg, Dwarf_Die die,
                    std::map<off_t, type_t>& types, 
                    elf& pelf);
  dw_types prototype_typname2int(const char *name);
  int prototype_add_args(Dwarf_Debug dbg, Dwarf_Die die,
                         std::map<off_t, type_t>& types, 
                         pdebug_info sym);
  int types_add(Dwarf_Debug dbg, Dwarf_Die die, 
                std::map<off_t, type_t>& types);
  void types_print(std::map<off_t, type_t>& types);

  int prototype_add_elf(Elf *elf, elf& pelf)
  {
    int ret;
    Dwarf_Debug dbg;
    Dwarf_Die die;
    Dwarf_Error err;
    Dwarf_Unsigned cu_header_length = 0;
    Dwarf_Unsigned abbrev_offset = 0;
    Dwarf_Half version_stamp = 0;
    Dwarf_Half address_size = 0;
    Dwarf_Unsigned next_cu_offset = 0;

    ret = dwarf_elf_init(elf, DW_DLC_READ, NULL, NULL, &dbg, &err);
    if(ret == DW_DLV_NO_ENTRY){
      return -1;
    }
    while ((ret = dwarf_next_cu_header(dbg, &cu_header_length, 
                                       &version_stamp, &abbrev_offset,
                                       &address_size, &next_cu_offset, 
                                       &err)) == DW_DLV_OK){
      ret = dwarf_siblingof(dbg, NULL, &die, &err);
      if(ret == DW_DLV_NO_ENTRY){
        continue;
      }else if(ret != DW_DLV_OK){
        break;
      }
        
      prototype_add_cu(dbg, die, pelf);
    }
    if(ret == DW_DLV_ERROR){
      dwarf_finish(dbg, &err);
      return -1;
    }
    dwarf_finish(dbg, &err);
    return 0;
  }

  int prototype_add_cu(Dwarf_Debug dbg, Dwarf_Die die, 
                       elf& pelf)
  {
    int ret;
    Dwarf_Error err;
    Dwarf_Half tag;
    Dwarf_Die child;

    while(1){
      ret = dwarf_tag(die, &tag, &err);
      if(ret != DW_DLV_OK){
        return -1;
      }
      if(tag == DW_TAG_compile_unit){
        ret = dwarf_child(die, &child, &err);
        if(ret == DW_DLV_ERROR){
          return -1;
        }if(ret == DW_DLV_OK){
          std::map<off_t, type_t> types;
          types_add(dbg, child, types);
          prototype_add(dbg, child, types, pelf);
#ifdef DEBUG
          types_print(types);
#endif
        }
      }
      ret = dwarf_siblingof(dbg, die, &die, &err);
      if(ret == DW_DLV_NO_ENTRY){
        break;
      }else if(ret != DW_DLV_OK){
        return -1;
      }
    }
    return 0;
  }

  int prototype_add(Dwarf_Debug dbg, Dwarf_Die die,
                    std::map<off_t, type_t>& types, 
                    elf& pelf)
  {
    int ret;
    Dwarf_Error err;
    Dwarf_Half tag;
    Dwarf_Die child;
    Dwarf_Attribute attr;
    char *name;
    Dwarf_Addr addr;

    while(1){
      ret = dwarf_tag(die, &tag, &err);
      if(ret != DW_DLV_OK){
        return -1;
      }   
      if(tag == DW_TAG_subprogram){
        ret = dwarf_attr(die, DW_AT_name, &attr, &err);
        if(ret != DW_DLV_OK){
          return -1;
        }
        ret = dwarf_formstring(attr, &name, &err);
        if(ret != DW_DLV_OK){
          return -1;
        }
        ret = dwarf_attr(die, DW_AT_low_pc, &attr, &err);
        if(ret != DW_DLV_OK){
          return -1;
        }
        ret = dwarf_formaddr(attr, &addr, &err);
        if(ret != DW_DLV_OK){
          return -1;
        }

        pdebug_info sym = pelf.get_debug_info((unsigned long)addr, false);
        if (!sym) {
          sym = pelf.get_debug_info((unsigned long)addr, true);
          assert (sym);
          ret = dwarf_child(die, &child, &err);
          if(ret == DW_DLV_OK){
            prototype_add_args(dbg, child, types, sym);
          }else if(ret == DW_DLV_ERROR){
            return -1;
          }
        } 
      }

      ret = dwarf_siblingof(dbg, die, &die, &err);
      if(ret == DW_DLV_NO_ENTRY){
        break;
      }else if(ret != DW_DLV_OK){
        return -1;
      }
    }
    return 0;
  }

  dw_types prototype_typname2int(const char *name)
  {
    if(!std::strcmp(name, "pointer")){
      return TYPE_POINTER;
    }else if(!std::strcmp(name, "int")){
      return TYPE_INT;
    }else if(!std::strcmp(name, "unsigned int")){
      return TYPE_UINT;
    }else if(!std::strcmp(name, "short int")){
      return TYPE_SHORT;
    }else if(!std::strcmp(name, "short unsigned int")){
      return TYPE_USHORT;
    }else if(!std::strcmp(name, "char")){
      return TYPE_CHAR;
    }else if(!std::strcmp(name, "unsigned char")){
      return TYPE_UCHAR;
    }else if(!std::strcmp(name, "long int")){
      return TYPE_LONG;
    }else if(!std::strcmp(name, "long unsigned int")){
      return TYPE_ULONG;
    }else if(!std::strcmp(name, "long long int")){
      return TYPE_LONGLONG;
    }else if(!std::strcmp(name, "long long unsigned int")){
      return TYPE_ULONGLONG;
    }else if(!std::strcmp(name, "size_t")){
      return TYPE_SIZE_T;
    }else if(!std::strcmp(name, "__off_t")){
      return TYPE_OFF_T;
    }else if(!std::strcmp(name, "__off64_t")){
      return TYPE_OFF64_T;
    }

    return TYPE_UNKNOWN;
  }

  int prototype_add_args(Dwarf_Debug dbg, Dwarf_Die die,
                         std::map<off_t, type_t>& types, 
                         pdebug_info sym) 
  {
    int ret;
    Dwarf_Error err;
    Dwarf_Half tag;
    Dwarf_Attribute attr;
    Dwarf_Off off;
    int type;
    char* name;

    while(1){
      ret = dwarf_tag(die, &tag, &err);
      if(ret != DW_DLV_OK){
        return -1;
      }

      if(tag == DW_TAG_formal_parameter){
        ret = dwarf_attr(die, DW_AT_name, &attr, &err);
        if(ret != DW_DLV_OK){
          return -1;
        }
        ret = dwarf_formstring(attr, &name, &err);
        if(ret != DW_DLV_OK){
          return -1;
        }
        ret = dwarf_attr(die, DW_AT_type, &attr, &err);
        if(ret != DW_DLV_OK){
          return -1;
        }
        ret = dwarf_formref(attr, &off, &err);
        if(ret != DW_DLV_OK){
          return -1;
        }
        type = off;

        std::map<off_t, type_t>::iterator iter = types.find(type);
        if(iter != types.end()){
          dw_types t = prototype_typname2int(iter->second.name.c_str());
          sym->add_arg(t, name, iter->second.size);
        }else{
          sym->add_arg(TYPE_UNKNOWN, name, 0);
        }
      }

      ret = dwarf_siblingof(dbg, die, &die, &err);
      if(ret == DW_DLV_NO_ENTRY){
        break;
      }else if(ret != DW_DLV_OK){
        return -1;
      }
    }
    return 0;
  }

  int types_add(Dwarf_Debug dbg, Dwarf_Die die, std::map<off_t, type_t>& types)
  {
    int ret;
    Dwarf_Error err;
    Dwarf_Half tag;
    Dwarf_Attribute attr;
    Dwarf_Signed size, encoding;
    Dwarf_Off offset;
    char *name;

    while(1){
      ret = dwarf_tag(die, &tag, &err);
      if(ret != DW_DLV_OK){
        return -1;
      }

      if(tag == DW_TAG_base_type){
        ret = dwarf_die_CU_offset(die, &offset, &err);
        ret = dwarf_attr(die, DW_AT_name, &attr, &err);
        if(ret != DW_DLV_OK){
          return -1;
        }
        ret = dwarf_formstring(attr, &name, &err);
        if(ret != DW_DLV_OK){
          return -1;
        }
        ret = dwarf_attr(die, DW_AT_byte_size, &attr, &err);
        if(ret != DW_DLV_OK){
          return -1;
        }
        ret = dwarf_formsdata(attr, &size, &err);
        if(ret != DW_DLV_OK){
          return -1;
        }
        ret = dwarf_attr(die, DW_AT_encoding, &attr, &err);
        if(ret != DW_DLV_OK){
          return -1;
        }
        ret = dwarf_formsdata(attr, &encoding, &err);
        if(ret != DW_DLV_OK){
          return -1;
        }

        type_t type;
        type.offset = offset;
        type.name = name;
        type.size = size;
        types.insert(std::make_pair(offset, type));
      }else if(tag == DW_TAG_pointer_type){
        ret = dwarf_die_CU_offset(die, &offset, &err);
        ret = dwarf_attr(die, DW_AT_byte_size, &attr, &err);
        if(ret != DW_DLV_OK){
          return -1;
        }
        ret = dwarf_formsdata(attr, &size, &err);
        if(ret != DW_DLV_OK){
          return -1;
        }
        type_t type;
        type.offset = offset;
        type.name = "pointer";
        type.size = size;
        types.insert(std::make_pair(offset, type));
      } else {
        // printf("tag=0x%x\n", tag);
      }

      ret = dwarf_siblingof(dbg, die, &die, &err);
      if(ret == DW_DLV_NO_ENTRY){
        break;
      }else if(ret != DW_DLV_OK){
        return -1;
      }
    }
    return 0;
  }

  void types_print_entry(const std::pair<off_t, type_t>&)
  {
    // printf("%ld: name=%s, size=%d\n", p.first, p.second.name.c_str(), 
    //        p.second.size);
    return;
  }

  void types_print(std::map<off_t, type_t>& types)
  {
    std::for_each(types.begin(), types.end(), types_print_entry);
  }

}

namespace hoge {
  int get_debug_info(pid_t pid, elf& pelf)
  {
    int fd;
    Elf *e;
    char buf[128] = {0};

    elf_version(EV_CURRENT);
    snprintf(buf, sizeof(buf) - 1, "/proc/%d/exe", pid);
    fd = ::open(buf, O_RDONLY);
    if(fd < 0){
      return -1;
    }
    e = elf_begin(fd, ELF_C_READ, (Elf*)0);
    prototype_add_elf(e, pelf);
    elf_end(e);

    // prototype_print(pelf);
    ::close(fd);
    return 0;
  }

  const char* str_dw_types(dw_types t)
  {
    switch(t) {
    case TYPE_POINTER: return "POINTER";    
    case TYPE_INT: return "int";        
    case TYPE_UINT: return "uint";       
    case TYPE_SHORT: return "short";      
    case TYPE_USHORT: return "ushort";     
    case TYPE_CHAR: return "char";       
    case TYPE_UCHAR: return "uchar";      
    case TYPE_LONG: return "long";       
    case TYPE_ULONG: return "ulong";      
    case TYPE_LONGLONG: return "longlong";   
    case TYPE_ULONGLONG: return "ulonglong";  
    case TYPE_SIZE_T: return "size_t";     
    case TYPE_OFF_T: return "off_t";      
    case TYPE_OFF64_T: return "off64_t"; 
    case TYPE_UNKNOWN: 
      ;
    }
    return "UNKNOWN";
  }

}
