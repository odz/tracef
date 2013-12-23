// $Id: xelf.h,v 1.18 2007/09/22 14:22:53 sato Exp $

#ifndef XELF_H_
#define XELF_H_

#include <set>
#include <map>
#include <list>
#include <string>

#include <boost/utility.hpp>
#include <boost/function.hpp>

#include <bfd.h>
#include <dis-asm.h>
#include "ftrace/prototype.h"

#if defined(__i386__) || defined(__x86_64__)
  #define HT_PLT_INSN_SIZE  6   /* ff 25 XX XX XX XX */
  #define HT_PLT_OFFSET     2   /* ff 25 */
  #define HT_MNEMONIC_RET  "ret"
  #define HT_MNEMONIC_HLT  "hlt"
  #define HT_DISASM_FN      print_insn_i386_att /* in libopcodes.a */
#else
  #error unknown arch
#endif 
#define HT_PLT_ADDR_SIZE   (HT_PLT_INSN_SIZE - HT_PLT_OFFSET)
#define HT_THROW_FUNCTION  "__cxa_throw@plt"

namespace hoge {
  typedef boost::shared_ptr<class debug_info> pdebug_info;
  class elf : boost::noncopyable {
  public:
    explicit elf(pid_t pid);
    ~elf() throw();
    std::string get_cmdline() const;

    void collect_information(bool read_synthetic_syms, 
                             bool find_ret_insn,       
                             bool read_file_line,      
                             bool read_argument_info,  
                             const std::set<std::string>& exclude_syms);
    bool has_sym() const { return ! symbols_.empty(); }

    std::string get_funcname(uintptr_t func_addr) const;
    bool get_funcname(uintptr_t func_addr, std::string& ret) const;
    std::string get_fileline(uintptr_t func_addr) const;
    uintptr_t get_func_addr(uintptr_t addr_at_ret_insn) const;
    bool get_func_addr(uintptr_t addr_at_ret, uintptr_t& ret) const;

    bool is_func_addr(uintptr_t addr) const;
    bool is_noret_func_addr(uintptr_t addr) const;

    sinsn_t get_byte_at(uintptr_t addr) const;
    void set_byte_at(uintptr_t addr, sinsn_t b);

    const std::map<uintptr_t, std::string>& get_symbols() const;
    const std::map<uintptr_t, uintptr_t>& get_ret_addrs() const;
    pdebug_info get_debug_info(uintptr_t func_addr, bool create = false);

    bool is_PLT_enter(uintptr_t pc);
    bool is_PLT_leave(uintptr_t pc);
    bool is_cxa_throw_addr(uintptr_t pc) 
    {
      return pc == cxa_throw_addr_;
    }
    
  private:
    void for_each_symbol(void* minisyms, 
                         unsigned int size,
                         long symcount,
                         boost::function<void (asymbol* sym)> f);

    long collect_symbols(void** minisyms,
                         unsigned int* size,
                         asymbol** synthsyms,
                         const std::set<std::string>& exclude_syms,
                         bool read_synthetic_syms);
    long collect_synthetic_symbols(void** minisyms,
                                   asymbol** synthsyms,
                                   long symcount) ;
    void do_collect_symbol(asymbol* sym);
    long filter_symbols(void* minisyms, unsigned int size, long symcount, 
                        const std::set<std::string>& exclude_syms);
    
    void collect_line_information(void* minisyms,
                                  unsigned int size,
                                  long symcount);
    void do_collect_line_infomation(asymbol** symbols, asymbol* sym);

    void collect_func_enter_insns(asection* secs[],
                                  size_t sec_sizes[],
                                  sinsn_t* sec_contents[]);

    void collect_func_leave_addresses(asection* secs[],
                                      size_t sec_sizes[],
                                      sinsn_t* sec_contents[]);

    void collect_func_leave_insns(asection* secs[],
                                  size_t sec_sizes[],
                                  sinsn_t* sec_contents[]);

    void collect_debug_infomation();
    
    asection* get_section(const char* name) const;
    sinsn_t*  get_section_contents(asection& sec, size_t& sec_size) const;
    
  private:
    bfd* abfd_;
    pid_t pid_;
    bool break_at_ret_;
    uintptr_t cxa_throw_addr_;

    // XXX: inefficient
    std::map<uintptr_t, std::string> symbols_;
    std::set<uintptr_t>              no_ret_funcs_;
    std::map<uintptr_t, std::string> fileline_;
    std::map<uintptr_t, sinsn_t>     insns_; // of func enter and leave
    std::map<uintptr_t, uintptr_t>   reta_to_funca_;
    std::map<uintptr_t, pdebug_info> dinfo_;
  };

  class debug_info : boost::noncopyable {
  public:
    class func_arg {
    public:
      func_arg(dw_types type, const std::string& name, std::size_t size)
        : type_(type), name_(name), size_(size) {}
      dw_types type_;
      std::string name_;
      std::size_t size_;
    };
    void add_arg(dw_types type, const std::string& name, std::size_t size) 
    {
      args_.push_back(func_arg(type, name, size));
    }
    const std::list<func_arg>& get_arg() const 
    {
      return args_;
    }
  private:
    std::list<func_arg> args_;
  };
}

// TODO: 
//   - PIE support
//   - object caching...

#endif
