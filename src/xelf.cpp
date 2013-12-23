// $Id: xelf.cpp,v 1.27 2007/09/24 13:33:37 sato Exp $

//
// this file is based on binutils-2.18/binutils/nm.c (http://www.gnu.org/).
//
// ( nm.c -- Describe symbol table of a rel file.
//   Copyright 1991, 1992, 1993, 1994, 1995, 1996, 1997, 1998, 1999, 2000,
//             2001, 2002, 2003, 2004, 2005, 2007
//   Free Software Foundation, Inc.)
//

#include "main.h"
#include "xelf.h"

#include <limits>
#include <cstdarg>
#include <climits>
#include <sstream>
#include <boost/bind.hpp>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef DEBUG
#include <iostream>
#include <boost/io/ios_state.hpp>
namespace {
  // std::stringstream dbg;
  std::ostream& dbg = std::cerr;
}
#endif

namespace {
  TLS_ char mnemonic[32];
  TLS_ int  count;

  int disasm_cb(FILE*, const char* fmt, ...)
  {
    va_list args;
    va_start(args, fmt);
    if (count == 0) {
      const char* str = va_arg(args, const char*);
      std::strncpy(mnemonic, str, sizeof(mnemonic) - 1);
      mnemonic[sizeof(mnemonic) - 1] = '\0';
      std::size_t spc_idx = std::strcspn(mnemonic, " ");
      mnemonic[spc_idx] = '\0';
      ++count;
#ifdef DEBUG
      dbg << " " << mnemonic;
#endif
    }
    va_end(args);
    return 0;
  }
  
  void reset_disasm_cb()
  {
    count = 0;
    mnemonic[0] = '\0'; // verbose?
  }

  std::list<uintptr_t> search_mnemonic(disassemble_info& disinfo, uintptr_t upper_bound,
                                       const char* search_for,
                                       const char* search_for2)
  {
    std::list<uintptr_t> rets;

    size_t bytes = 0;
    while (bytes < disinfo.buffer_length) {
      reset_disasm_cb();
      long size = HT_DISASM_FN(disinfo.buffer_vma + bytes, &disinfo);
      if (!strcasecmp(mnemonic, search_for) ||
          !strcasecmp(mnemonic, search_for2)) {
        // found ret or hlt
        uintptr_t ret_addr = disinfo.buffer_vma + bytes;
        if (ret_addr >= upper_bound) {
          return rets;
        }
        rets.push_back(ret_addr);
      }
      bytes += size;
    }
    return rets;
  }

  bool is_in_section(asection* sec, size_t sec_size, uintptr_t addr)
  {
    assert(sec);
    if ((addr >= (sec->vma)) && (addr < (sec->vma + sec_size))) {
      return true;
    }
    return false;
  }
}

namespace hoge {

  elf::elf(pid_t pid)
    : abfd_(NULL), pid_(pid), break_at_ret_(false),
      cxa_throw_addr_(0)
  {
    bfd_init();

    char filename[128] = {0};
    ::snprintf(filename, sizeof(filename) - 1, 
               "/proc/%d/exe", pid);

    abfd_ = bfd_openr(filename, NULL);
    if (abfd_ == NULL) {
      THROW_STR("can't open file", filename);
    }

    if (! bfd_check_format(abfd_, bfd_object)) {
      bfd_close(abfd_);
      THROW_STR("!bfd_object", get_cmdline());
    }
  }

  elf::~elf() throw()
  {
    bfd_close(abfd_);
  }

  std::string elf::get_cmdline() const
  {
    char buf[PATH_MAX + 1] = {0};
    char filename[128] = {0};

    ::snprintf(filename, sizeof(filename) - 1, 
               "/proc/%d/cmdline", pid_);

    int fd = ::open(filename, O_RDONLY);
    if (fd < 0) {
      THROW_STR("can't open file", filename);
    }
    ssize_t bytes = ::read(fd, buf, PATH_MAX);
    ::close(fd);
    if (bytes < 0) {
      THROW_STR("read error", filename);
    }
    buf[bytes] = '\0'; // verbose?

#ifdef DEBUG
    dbg << "filename for pid " << pid_ << ": " 
        << buf << std::endl;
#endif
    // now buf is a '\0'-terminated array.
    return buf; // returns first element. 
  }

  sinsn_t elf::get_byte_at(uintptr_t addr) const
  {
    std::map<uintptr_t, sinsn_t>::const_iterator iter
      = insns_.find(addr);
    if (iter == insns_.end()) {
      THROW_HEX("unknown address", addr);
    }
    return iter->second;
  }

  bool elf::get_func_addr(uintptr_t addr_at_ret, uintptr_t& ret) const
  {
    std::map<uintptr_t, uintptr_t>::const_iterator iter 
      = reta_to_funca_.find(addr_at_ret);
    if (iter == reta_to_funca_.end()) {
      return false;
    }
    ret = iter->second;
    return true;
  }

  uintptr_t elf::get_func_addr(uintptr_t addr_at_ret) const
  {
    uintptr_t ret;
    if (! get_func_addr(addr_at_ret, ret)) {
      THROW_HEX("unknown address", addr_at_ret);
    }
    return ret;
  }

  bool elf::get_funcname(uintptr_t func_addr, std::string& ret) const
  {
    std::map<uintptr_t, std::string>::const_iterator iter
      = symbols_.find(func_addr);
    if (iter == symbols_.end()) {
      return false;
    }
    ret = iter->second;
    return true;
  }

  std::string elf::get_funcname(uintptr_t func_addr) const
  {
    std::string ret;
    if (! get_funcname(func_addr, ret)) {
      THROW_HEX("unknown address", func_addr);
    }
    return ret;
  }

  std::string elf::get_fileline(uintptr_t func_addr) const
  {
    std::map<uintptr_t, std::string>::const_iterator iter
      = fileline_.find(func_addr);
    if (iter == fileline_.end()) {
      THROW_HEX("unknown address", func_addr);
    }
    return iter->second;
  }

  const std::map<uintptr_t, std::string>& 
  elf::get_symbols() const
  {
    return symbols_;
  }

  const std::map<uintptr_t, uintptr_t>& 
  elf::get_ret_addrs() const
  {
    // map: address of 'ret' insn -> func address
    return reta_to_funca_;
  }

  bool elf::is_func_addr(uintptr_t addr) const
  {
    std::map<uintptr_t, std::string>::const_iterator iter
      = symbols_.find(addr);
    return (iter != symbols_.end());
  }

  bool elf::is_noret_func_addr(uintptr_t addr) const
  {
    std::set<uintptr_t>::const_iterator iter = no_ret_funcs_.find(addr);
    return (iter != no_ret_funcs_.end());
  }

  static const char* section_names[] = { ".text", ".plt", ".init", ".fini" };
  static const size_t num_sec = HT_LENGTHOF(section_names);

  asection* elf::get_section(const char* name) const
  {
    return bfd_get_section_by_name(abfd_, name);
  }

  sinsn_t* elf::get_section_contents(asection& sec, size_t& sec_size) const
  {
    sec_size = bfd_section_size(abfd_, &sec);
    sinsn_t* ret = (sinsn_t*)std::calloc(sec_size, sizeof(sinsn_t));
    if (ret) {
      bool ok UNUSED_ = bfd_get_section_contents(abfd_, &sec, ret, 0, sec_size);
      assert(ok);
    }
    return ret;
  }

  void elf::collect_information(bool read_synthetic_syms,  
                                bool find_ret_insn,        
                                bool read_file_line,       
                                bool read_argument_info,   
                                const std::set<std::string>& exclude_syms)
  {
    if (! (bfd_get_file_flags(abfd_) & HAS_SYMS)) {
      // no symbols
      return;
    }

    std::size_t i;
    void* minisyms = NULL;
    unsigned int size = 0; 
    asymbol* synthsyms = NULL;

    const long symcount    /* static symbol + synthetic symbol */
      = collect_symbols(&minisyms, &size, &synthsyms, 
                        exclude_syms, read_synthetic_syms);
    assert(minisyms != NULL && symcount >= 0);

    if (symcount && read_file_line) {
      collect_line_information(minisyms, size, symcount);
    }
    
    if (symcount) {
      asection* secs[num_sec];
      size_t sec_sizes[num_sec];
      sinsn_t* sec_contents[num_sec];
      
      for (i = 0; i < num_sec; ++i) {
        secs[i] = get_section(section_names[i]);
        if (! secs[i]) return;
        sec_contents[i] = get_section_contents(*(secs[i]), sec_sizes[i]); 
        if (! sec_contents[i]) return; // XXX: support for big .text
      }

      collect_func_enter_insns(secs, sec_sizes, sec_contents);

      if (find_ret_insn) {      
        break_at_ret_ = true;
        collect_func_leave_addresses(secs, sec_sizes, sec_contents);
        collect_func_leave_insns(secs, sec_sizes, sec_contents);
      }

      for (i = 0; i < num_sec; ++i) {
        std::free(sec_contents[i]);
      }
    }
    
    if (symcount && read_argument_info) {
      collect_debug_infomation();
    }

    std::free(minisyms);
    std::free(synthsyms); /* minisym points to synthsym's element */
  }

  long elf::collect_symbols(void** minisyms,
                            unsigned int* size,
                            asymbol** synthsyms,
                            const std::set<std::string>& exclude_syms,
                            bool read_synthetic_syms)
  {
    long symcount = bfd_read_minisymbols(abfd_, 0, minisyms, size);
    if (symcount <= 0) {
      // no symbols?
      return 0;
    }

    if (read_synthetic_syms) {
      assert(*size == sizeof(asymbol*));
      symcount = collect_synthetic_symbols(minisyms, synthsyms, symcount);
      assert(symcount > 0);
    }

    symcount = filter_symbols(*minisyms, *size, symcount,
                              exclude_syms);
    for_each_symbol(*minisyms, *size, symcount,
                    boost::bind(&elf::do_collect_symbol, this, _1));

    return symcount;
  }

  void elf::collect_line_information(void* minisyms,
                                     unsigned int size,
                                     long symcount)
  {
    long symsize = bfd_get_symtab_upper_bound(abfd_);
    if (symsize < 0) {
      return; // no symbols?
    }

    asymbol** symbols = (asymbol**)std::malloc(symsize);
    long symcount_tmp_ UNUSED_ = bfd_canonicalize_symtab(abfd_, symbols);
    assert(symcount_tmp_ > 0);

    for_each_symbol(minisyms, size, symcount,
                    boost::bind(&elf::do_collect_line_infomation,
                                this, symbols, _1));
    std::free(symbols);
  }

  void elf::for_each_symbol(void* minisyms, 
                            unsigned int size,
                            long symcount,
                            boost::function<void (asymbol* sym)> f)
  {
    asymbol* store = bfd_make_empty_symbol(abfd_);
    if (store == NULL) { THROW_STR("can't make empty symbol", ""); }
    bfd_byte* from = (bfd_byte *)minisyms;
    bfd_byte* fromend = from + symcount * size;
    for (; from < fromend; from += size) {
      asymbol* sym = bfd_minisymbol_to_symbol(abfd_, 0, from, store);
      assert(sym != NULL);
      f(sym);
    }
  }

  void elf::do_collect_symbol(asymbol* sym)
  {
    symbol_info syminfo;
    bfd_get_symbol_info(abfd_, sym, &syminfo);
    symbols_.insert(std::make_pair(syminfo.value, syminfo.name));

#ifdef DEBUG
    {
      boost::io::ios_flags_saver saver(dbg); // RAII
      dbg << "symbol found at 0x" << std::hex << syminfo.value 
          << ": " << syminfo.name << std::endl;
    }
#endif
  }

  void elf::do_collect_line_infomation(asymbol** symbols, asymbol* sym)
  {
    if (bfd_get_section(sym)->owner == abfd_) {
      const char* functionname = NULL; /* dummy */
      const char* filename = NULL;
      unsigned int lineno = 0;

      //
      // Valgrind says that there's memory leak in bfd_find_line and 
      // bfd_find_nearest_line functions.
      // Valgrind also reports the same leakage for 'nm -l foo'
      //
      // Anyway, needs more investigation....
      //
      if ((
#ifdef USE_BFD_FIND_LINE
           bfd_find_line(abfd_, symbols, sym, &filename, &lineno) 
#else
           0 /* optimization */
#endif
           || bfd_find_nearest_line(abfd_, bfd_get_section(sym),
                                    symbols, 
                                    sym->value, /* offset inside the section? */ 
                                    &filename, &functionname, &lineno)) && 
          filename != NULL && lineno != 0) {

        // lineno information found
        symbol_info syminfo;
        std::stringstream ss;
        
        bfd_get_symbol_info(abfd_, sym, &syminfo);
        ss << filename << ":" << lineno;
        fileline_.insert(std::make_pair(syminfo.value, ss.str()));

#ifdef DEBUG
        dbg << "lineno found: " << syminfo.name 
            << "() = [" << ss.str() << "]" << std::endl;
#endif
      }
    }
  }
 
  void elf::collect_func_enter_insns(asection* secs[],
                                     size_t sec_sizes[],
                                     sinsn_t* sec_contents[])
  {
    std::map<uintptr_t, std::string>::const_iterator 
      iter, eiter = symbols_.end();
    for(iter = symbols_.begin(); iter != eiter; ++iter) {
      bool found UNUSED_ = false;
      const uintptr_t& addr = iter->first;
      for (std::size_t i = 0; i < num_sec; ++i) {
        if (is_in_section(secs[i], sec_sizes[i], addr)) {
          // insn found in this section
          sinsn_t insn = (sec_contents[i])[addr - (secs[i]->vma)];
          insns_.insert(std::make_pair(addr, insn));
          found = true;
#ifdef DEBUG
          {
            boost::io::ios_flags_saver saver(dbg); // RAII
            dbg << "[enter] insn found: addr 0x" << std::hex << addr
                << " = 0x" << std::hex << (unsigned int)insn << std::endl;
          }
#endif
          break;
        }
      }
#ifdef DEBUG
      if (!found) {
        boost::io::ios_flags_saver saver(dbg); // RAII
        dbg << "can't find insn: addr 0x" << std::hex << addr << std::endl;
      }
#endif
    }
  }

  void elf::collect_func_leave_addresses(asection* secs[],
                                         size_t sec_sizes[],
                                         sinsn_t* sec_contents[])
  {
    disassemble_info disinfo;
    std::memset(&disinfo, 0, sizeof(disinfo));

    INIT_DISASSEMBLE_INFO(disinfo, stdout, disasm_cb);
    disinfo.arch    = bfd_get_arch(abfd_);
    disinfo.mach    = bfd_mach_i386_i386;
    disinfo.flavour = bfd_get_flavour(abfd_);
    disinfo.endian  = abfd_->xvec->byteorder;
    disinfo.display_endian = BFD_ENDIAN_LITTLE;

    std::map<uintptr_t, std::string>::const_reverse_iterator 
      iter, eiter = symbols_.rend();

    uintptr_t last_addr = std::numeric_limits<uintptr_t>::max(); // unknown
    for(iter = symbols_.rbegin(); iter != eiter; ++iter) {
      const uintptr_t& addr = iter->first;

      // don't handle __cxa_throw@plt for some magic reasons...
      if (iter->second == HT_THROW_FUNCTION) {
        cxa_throw_addr_ = addr;
        no_ret_funcs_.insert(addr);
        continue;
      }

      for (std::size_t i = 0; i < num_sec; ++i) {
        if (! is_in_section(secs[i], sec_sizes[i], addr)) {
          continue;
        }
        // function found in this section
#ifdef DEBUG
        {
          boost::io::ios_flags_saver saver(dbg); // RAII
          dbg << "search for ret/hlt insn: func 0x" 
              << std::hex << addr 
              << ": " << symbols_.find(addr)->second
              << std::endl;
        }
#endif
        if (section_names[i] == std::string(".plt")) {
          uintptr_t ret = addr + HT_PLT_INSN_SIZE;
#ifdef DEBUG
          {
            boost::io::ios_flags_saver saver(dbg); // RAII
            dbg << "'ret' point for PLT found: func 0x" << std::hex << addr
                << ": " << symbols_.find(addr)->second << ": "
                << " returns at 0x" << std::hex << ret << std::endl;
          }
#endif
          bool new_addr
            = reta_to_funca_.insert(std::make_pair(ret, addr)).second;
          if (!new_addr) {
            no_ret_funcs_.insert(addr);
          }
        } else {
          uintptr_t dif = addr - secs[i]->vma;
          disinfo.section       = secs[i];
          disinfo.buffer        = sec_contents[i] + dif;
          disinfo.buffer_length = sec_sizes[i]    - dif;
          disinfo.buffer_vma    = addr;
          std::list<uintptr_t> rets
            = search_mnemonic(disinfo, last_addr,
                              HT_MNEMONIC_RET, HT_MNEMONIC_HLT);
          if (rets.empty()) {
            no_ret_funcs_.insert(addr);
#ifdef DEBUG
            {
              boost::io::ios_flags_saver saver(dbg); // RAII
              dbg << "RET INSN NOT FOUND for func 0x" 
                  << std::hex << addr
                  << ": " << symbols_.find(addr)->second
                  << std::endl;
            }
#endif
          } else if (rets.size() != 1) {
#ifdef DEBUG
            {
              boost::io::ios_flags_saver saver(dbg); // RAII
              // GCC tends to generate multiple rets from switch-case stmt.
              dbg << "MULTIPLE RET (" << std::dec << rets.size() 
                  << ") FOUND for func 0x" 
                  << std::hex << addr
                  << ": " << symbols_.find(addr)->second
                  << std::endl;
            }
#endif
          }
          std::list<uintptr_t>::const_iterator iter;
          for (iter = rets.begin(); iter != rets.end(); ++iter) {
#ifdef DEBUG
            {
              boost::io::ios_flags_saver saver(dbg); // RAII
              // case 1. tail recursion optimization applied?
              // case 2. the func never returns, but throws?
              // case 3. the func calls __attribute__((noreturn)) func, 
              //         or the func itself is no-returing function?
              dbg << "ret/hlt insn found: func 0x" << std::hex << addr
                  << ": " << symbols_.find(addr)->second << ": "
                  << " returns at 0x" << std::hex << *iter
                  << " [non-PLT]" << std::endl;
            }
#endif
            bool new_addr UNUSED_
              = reta_to_funca_.insert(std::make_pair(*iter, addr)).second;
#ifdef DEBUG
            if (!new_addr) {
              boost::io::ios_flags_saver saver(dbg); // RAII
              dbg << "RET INSN at 0x" 
                  << std::hex << *iter
                  << " IS ALREADY REGISTERED: func 0x" 
                  << std::hex << addr << ": " 
                  << symbols_.find(addr)->second
                  << std::endl;
            }
#endif
          } // for iter
        }
        break;
      } // for each section
      last_addr = addr;
    } // for each symbol
  }

  void elf::collect_func_leave_insns(asection* secs[],
                                     size_t sec_sizes[],
                                     sinsn_t* sec_contents[])
  {
    std::map<uintptr_t, uintptr_t>::const_iterator 
      iter, eiter = reta_to_funca_.end();
    for(iter = reta_to_funca_.begin(); iter != eiter; ++iter) {
      bool found = false;
      for (std::size_t i = 0; i < num_sec; ++i) {
        const uintptr_t& addr = iter->first;
        if (is_in_section(secs[i], sec_sizes[i], addr)) {
          // insn found in this section
          sinsn_t insn = (sec_contents[i])[addr - (secs[i]->vma)];
          insns_.insert(std::make_pair(addr, insn)).second;
          found = true;
#ifdef DEBUG
          {
            boost::io::ios_flags_saver saver(dbg); // RAII
            dbg << "[leave] insn found: addr 0x" << std::hex << addr
                << " = 0x" << std::hex << (unsigned int)insn << std::endl;
          }
#endif
          break;
        }
      }
      assert(found);
    }
  }

  // detail
  long elf::collect_synthetic_symbols(void** minisyms,
                                      asymbol** synthsyms,
                                      long symcount) 
  {
    // collect synthetic symbols such as 'printf@plt'
    *synthsyms = NULL;

    long dyn_count = 0;
    asymbol** dyn_syms = NULL;
    long storage = bfd_get_dynamic_symtab_upper_bound(abfd_);
    
    if (storage > 0) {
      dyn_syms = (asymbol**)std::malloc(storage);
      dyn_count = bfd_canonicalize_dynamic_symtab(abfd_, dyn_syms);
      if (dyn_count < 0) {
        std::free(dyn_syms);
        THROW_STR("no symbols? (dyn_count<0)", get_cmdline());
      }
    }
    
    long synth_count = bfd_get_synthetic_symtab(abfd_, symcount,
                                                (asymbol**)*minisyms,
                                                dyn_count, dyn_syms, 
                                                synthsyms);
    if (synth_count > 0)  {
      asymbol **symp;
      void* new_mini 
        = std::malloc((symcount + synth_count + 1) * sizeof(*symp));
      symp = (asymbol**)new_mini;
      std::memcpy(symp, *minisyms, symcount * sizeof(*symp));
      symp += symcount;
      for (long i = 0; i < synth_count; i++) {
        *symp++ = (*synthsyms) + i;
      }
      *symp = NULL;
      std::free(*minisyms);
      *minisyms = new_mini;
    }
    std::free(dyn_syms);

    return symcount + synth_count;
  }

  // detail
  long elf::filter_symbols(void* minisyms, unsigned int size, long symcount, 
                           const std::set<std::string>& exclude_syms UNUSED_)
  {
    // XXX: should use for_each

    asymbol* store = bfd_make_empty_symbol(abfd_);
    if (store == NULL) { THROW_STR("can't make empty symbol", ""); }

    bfd_byte* from = (bfd_byte *)minisyms;
    bfd_byte* fromend = from + symcount * size;
    bfd_byte* to = (bfd_byte *)minisyms;

    for (; from < fromend; from += size) {
      bool keep = true;
      asymbol* sym = bfd_minisymbol_to_symbol(abfd_, 0,
                                              (const void *)from, store);
      assert(sym != NULL);

      if ((sym->flags & BSF_DEBUGGING) != 0)
        keep = false; 

      // filter out "t .L12345" syms 
      if (keep && (! (sym->flags & BSF_FUNCTION))) 
        keep = false; 

#if defined(bfd_is_target_special_symbol)
      // binutils >= 2.17
      if (keep && bfd_is_target_special_symbol(abfd_, sym)) 
        keep = false;
#endif

      if (keep) {
        symbol_info syminfo;
        bfd_get_symbol_info(abfd_, sym, &syminfo);

        // filter out 'U' (undefined) syms. 
        if (syminfo.type != 'T' && syminfo.type != 't' && 
            syminfo.type != 'W' && syminfo.type != 'w') 
          keep = false; 

#if 0
        // We can't exclude syms here not to miss function boundary in search_mnemonic()...
        if (keep && (exclude_syms.find(syminfo.name) != exclude_syms.end())) 
          keep = false;
#endif
      }

      if (keep) {
        memcpy(to, from, size);
        to += size;
      }
    }

    return (to - (bfd_byte *)minisyms) / size;
  }

  void elf::set_byte_at(uintptr_t addr, sinsn_t b) 
  {
    std::map<uintptr_t, sinsn_t>::size_type s = insns_.erase(addr);
    if (s != 1) {
      THROW_HEX("unknown address", addr);
    }
    insns_.insert(std::make_pair(addr, b));
  }

  bool elf::is_PLT_leave(uintptr_t pc)
  {
    if ((! break_at_ret_) || (pc <= HT_PLT_INSN_SIZE)) {
      return false;
    }

    uintptr_t func_addr;
    if (get_func_addr(pc, func_addr) &&
        (pc == func_addr + HT_PLT_INSN_SIZE)) {
      std::string fn;
      if (get_funcname(func_addr, fn) && 
          (fn.find("@plt") != std::string::npos)) {
        return true;
      }
    }

    return false;
  }

  bool elf::is_PLT_enter(uintptr_t pc)
  {
    if (! break_at_ret_) {
      return false;
    }

    std::string fn;
    if (get_funcname(pc, fn) && 
        (fn.find("@plt") != std::string::npos)) {
      return true;
    }

    return false;
  }

  pdebug_info elf::get_debug_info(uintptr_t func_addr, bool create)
  {
    pdebug_info null;
    std::map<uintptr_t, pdebug_info>::iterator iter = dinfo_.find(func_addr);
    if (iter == dinfo_.end()) {
      if (!create) {
        return null;
      }
      pdebug_info ret(new debug_info);
      dinfo_.insert(std::make_pair(func_addr, ret));
      return ret;
    }
    return iter->second;
  }

  void elf::collect_debug_infomation()
  {
    hoge::get_debug_info(pid_, *this); // in ftrace/prototype.c
  }

}

