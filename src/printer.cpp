// $Id: printer.cpp,v 1.38 2007/09/24 07:57:14 sato Exp $

#include "main.h"

#include <string>
#include <iomanip>
#include <iostream>
#include <boost/bind.hpp>
#include <boost/io/ios_state.hpp>
#include <boost/preprocessor/stringize.hpp>

#include <ctime>
#include <cstdio>
#include <cstring>
#include <sys/time.h>
#include <sys/ptrace.h>
#include <sys/user.h>

#include "process.h"
#include "printer.h"

#if SIZEOF_VOID_P == 4
#define A_FMT "0x%08zx"
#endif
#if SIZEOF_VOID_P == 8
#define A_FMT "0x%016zx"
#endif

namespace {
  const char* signalent[] = {
#include "signalent.h"
  };
  const int nsignals = HT_LENGTHOF(signalent);

  inline void dfl_print_pid(std::ostream& ost, hoge::process& current_proc,
                            bool p_pid) 
  {
    if (!p_pid) return;

    ost << "[pid " << current_proc.get_pid() << "] "; 
  }

  void dfl_print_current_time(std::ostream& ost,
                              bool p_time, bool p_time_usec)
  {
    if (!p_time && !p_time_usec) return;

    timeval tv;
    ::gettimeofday(&tv, NULL);
    
    tm tmbuf;
    ::localtime_r(&(tv.tv_sec), &tmbuf);

    char buf[20] = {0};
    if (p_time_usec) {
      std::snprintf(buf, sizeof(buf) - 1, "%02d:%02d:%02d.%06ld ", 
                    tmbuf.tm_hour, tmbuf.tm_min, tmbuf.tm_sec, tv.tv_usec);
    } else {
      std::snprintf(buf, sizeof(buf) - 1, "%02d:%02d:%02d ", 
                    tmbuf.tm_hour, tmbuf.tm_min, tmbuf.tm_sec);
    }
    ost << buf;
  }

  void dfl_print_argument(std::ostream& ost, hoge::process& current_proc, 
                          uintptr_t pc, 
                          bool p_argument, bool p_argument_val) 
  {
    if (!p_argument) return;

    const std::list<hoge::debug_info::func_arg>* args 
      = current_proc.get_function_arguments(pc);
    if (!args) return;

    bool unknown = false;
    char buf[32] = {0};

    uintptr_t sp = current_proc.get_sp() + sizeof(uintptr_t); 
    std::list<hoge::debug_info::func_arg>::const_iterator 
      iter = args->begin();
    while(iter != args->end()) {
      if (iter != args->begin()) { ost << ", "; }
      ost << str_dw_types(iter->type_) << " " << iter->name_;
      if (p_argument_val) {
        ost << " <";
        uintptr_t arg_data = current_proc.peek_memory(sp);
        switch (iter->type_) {
        case hoge::TYPE_UNKNOWN:
          snprintf(buf, sizeof(buf) - 1, A_FMT, arg_data);
          unknown = true;
          break;
        case hoge::TYPE_POINTER:
          snprintf(buf, sizeof(buf) - 1, A_FMT, arg_data);
          break;
        case hoge::TYPE_INT:  case hoge::TYPE_SHORT:
        case hoge::TYPE_CHAR: case hoge::TYPE_LONG:
          snprintf(buf, sizeof(buf) - 1, "%ld", (signed long)arg_data);
          break;
        case hoge::TYPE_UINT:   case hoge::TYPE_USHORT:
        case hoge::TYPE_UCHAR:  case hoge::TYPE_ULONG:
        case hoge::TYPE_SIZE_T: case hoge::TYPE_OFF_T:
          snprintf(buf, sizeof(buf) - 1, "%zu", arg_data);
          break;
        case hoge::TYPE_LONGLONG: case hoge::TYPE_OFF64_T:
        case hoge::TYPE_ULONGLONG:
          sp += sizeof(long);
          uintptr_t arg_data2 = current_proc.peek_memory(sp);
          unsigned long long arg64 
            = ((unsigned long long)arg_data2 << 32) | arg_data;
          if (iter->type_ == hoge::TYPE_ULONGLONG) {
            snprintf(buf, sizeof(buf) - 1, "%llu", arg64);
          } else {
            snprintf(buf, sizeof(buf) - 1, "%lld", (signed long long)arg64);
          }
          break;
        }
        ost << buf << (unknown ? "?" : "") << ">";
      }
      ++iter; sp += sizeof(uintptr_t); 
    }

    return;
  }

  void print_indent(std::ostream& ost, int indent, int scale)
  {
    assert(indent >= 0 && scale >= 0); 
    unsigned long num = indent * static_cast<unsigned long>(scale);
    //    for (unsigned long i = 0; i < num; ++i) 
    if (num) {
      ost << std::setw(num) << ' ';
    }
  }
}

namespace hoge {

  printer::printer(process_printer_t attach_info_printer,
                   process_printer_t detach_info_printer,
                   process_printer_t function_info_printer,
                   process_printer_t signal_info_printer,
                   process_printer_t exec_info_printer,
                   process_printer_t symbol_info_printer)
    : attach_info_printer_(attach_info_printer),
      detach_info_printer_(detach_info_printer),
      function_info_printer_(function_info_printer),
      signal_info_printer_(signal_info_printer),
      exec_info_printer_(exec_info_printer),
      symbol_info_printer_(symbol_info_printer) 
  {}

  default_printer::default_printer(boost::shared_ptr<const cl_options> opts) 
    : printer(boost::bind(&default_printer::print_attach_info,  
                          this, _1), 
              boost::bind(&default_printer::print_detach_info, 
                          this, _1), 
              boost::bind(&default_printer::print_function_info, 
                          this, _1), 
              boost::bind(&default_printer::print_signal_info, 
                          this, _1), 
              boost::bind(&default_printer::print_exec_info, 
                          this, _1),
              boost::bind(&default_printer::print_symbol_info, 
                          this, _1)),
      opts_(opts)
  {} 

#define OST (opts_->ost(current_proc.get_pid()))
#define XOST(get_parent)                        \
  (get_parent ?                                 \
   opts_->ost(current_proc.get_ppid()) :         \
   opts_->ost(current_proc.get_pid()))

  void default_printer::print_attach_info(hoge::process& current_proc) 
  {
    char buf[256] = {0};
    std::snprintf(buf, sizeof(buf) - 1, 
                  "+++ %s %d attached (ppid %d) +++",
                  current_proc.is_thread() ? "thread " : "process", 
                  current_proc.get_pid(),  
                  current_proc.get_ppid());  
 
    for (std::size_t i = 0; i < 2; ++i) {
      if (i == 0 || 
          (opts_->output_per_pid_ && 
           (current_proc.get_ppid() != current_proc.get_tracer_pid()))) {
        dfl_print_pid(XOST(i == 1), current_proc, opts_->print_pid_);
        dfl_print_current_time(XOST(i == 1),
                               opts_->print_time_, opts_->print_time_usec_);
        XOST(i == 1) << buf << std::endl;
      }
    }
  }

  void default_printer::print_detach_info(hoge::process& current_proc) 
  {
    char buf[256] = {0};

    trace_event ev = current_proc.get_last_event(); 
    if (ev == hoge::EV_SIG_EXIT) {
      int signo = current_proc.get_last_signal();
      std::snprintf(buf, sizeof(buf) - 1, 
                    "+++ %s %d (ppid %d) KILLED by %s (#%d %s) +++",
                    current_proc.is_thread() ? "thread " : "process", 
                    current_proc.get_pid(),  
                    current_proc.get_ppid(), 
                    (signo < nsignals ? signalent[signo] : "SIGNAL"),
                    signo, sys_siglist[signo]);
    } else {
      std::snprintf(buf, sizeof(buf) - 1, 
                    "+++ %s %d detached (ppid %d) +++",
                    current_proc.is_thread() ? "thread " : "process", 
                    current_proc.get_pid(),  
                    current_proc.get_ppid());  
    }

    for (std::size_t i = 0; i < 2; ++i) {
      if (i == 0 || 
          (opts_->output_per_pid_ && 
           (current_proc.get_ppid() != current_proc.get_tracer_pid()))) {
        dfl_print_pid(XOST(i == 1), current_proc, opts_->print_pid_);
        dfl_print_current_time(XOST(i == 1),
                               opts_->print_time_, opts_->print_time_usec_);
        XOST(i == 1) << buf << std::endl;
      }
    }
  }

  void default_printer::print_signal_info(hoge::process& current_proc)
  {
    char buf[128] = {0};
    char addr[32] = {0};

    if (!current_proc.is_tracing()) return;

    dfl_print_pid(OST, current_proc, opts_->print_pid_);
    dfl_print_current_time(OST,
                           opts_->print_time_, opts_->print_time_usec_);

    if (current_proc.get_last_event() == hoge::EV_SIGNALED_CRITICAL) {
      const siginfo_t& si = current_proc.get_last_signal_info();
      std::snprintf(addr, sizeof(addr) - 1, 
                    ", PC=" A_FMT ", MEM=" A_FMT, 
                    current_proc.get_pc(),
                    (uintptr_t)si.si_addr);
    }

    int signo = current_proc.get_last_signal();
    std::snprintf(buf, sizeof(buf) - 1, 
                  "--- %s received (#%d %s)%s ---", 
                  (signo < nsignals ? signalent[signo] : "SIGNAL"),
                  signo, sys_siglist[signo], addr);

    OST << buf << std::endl;
  }

  void default_printer::print_exec_info(hoge::process& current_proc)
  {
    if (!current_proc.is_tracing()) return;

    dfl_print_pid(OST, current_proc, opts_->print_pid_);
    dfl_print_current_time(OST, 
                           opts_->print_time_, opts_->print_time_usec_);
    OST << "=== execve(2) called. reloading symbols... ===" << std::endl;
  }

  // called when symbol is ready
  void default_printer::print_symbol_info(hoge::process& current_proc) 
  {
    if (!current_proc.is_tracing()) return;

    dfl_print_pid(OST, current_proc, opts_->print_pid_);
    dfl_print_current_time(OST, 
                           opts_->print_time_, opts_->print_time_usec_);

    OST << "=== symbols loaded: '"
        << current_proc.get_cmdline() 
        << "' ===" << std::endl;
  }

  void default_printer::print_function_info(hoge::process& current_proc) 
  {
    if (!current_proc.is_tracing()) return;

    const uintptr_t pc = current_proc.get_pc() - BREAKPOINT_INSN_LEN;
    if (!opts_->print_call_tree_ || current_proc.is_func_addr(pc)) {
      // enter
      if (opts_->exclude_syms_.find(current_proc.get_funcname(pc, false))
          != opts_->exclude_syms_.end()) {
          return;
      }

      dfl_print_pid(OST, current_proc, opts_->print_pid_);
      dfl_print_current_time(OST, 
                             opts_->print_time_, opts_->print_time_usec_);

      if (opts_->print_call_tree_) {
        size_t indent = current_proc.get_call_level();
        print_indent(OST, indent, opts_->offset_);
        OST << "==> ";
      } 

      OST << current_proc.get_funcname(pc, opts_->demangle_) << "(";
      dfl_print_argument(OST, 
                         current_proc, pc, 
                         opts_->print_func_argument_,
                         opts_->print_func_argument_value_); 
      OST << ") ";
      
      if (opts_->print_func_addr_) {
        char buf[32] = {0};
        std::snprintf(buf, sizeof(buf) - 1, "at " A_FMT, pc);
        OST << buf;
      }
      
      if (opts_->print_file_line_) {
        std::string fn = current_proc.get_fileline(pc);
        if (fn != HT_UNKNOWN_FILENAME) {
          OST << " [" << fn << "] ";  
        }
      }
    } else {
      // leave
      try {
        uintptr_t func_addr = current_proc.get_func_addr(pc);

        if (opts_->exclude_syms_.find(current_proc.get_funcname(func_addr, false))
            != opts_->exclude_syms_.end()) {
          return;
        }

        dfl_print_pid(OST, current_proc, opts_->print_pid_);
        dfl_print_current_time(OST, 
                               opts_->print_time_, opts_->print_time_usec_);

        user_regs_struct regs;
        current_proc.get_regs(regs);
        size_t indent = current_proc.get_call_level();
        print_indent(OST, indent, opts_->offset_);
        boost::io::ios_flags_saver saver(OST); // RAII
        OST << "<== "
            << current_proc.get_funcname(func_addr, opts_->demangle_)
            << "() [" << BOOST_PP_STRINGIZE(RETVAL_) 
            << " = 0x" << std::hex << regs.RETVAL_ 
            << "]";
      } catch(...) {
        // unknown return insn. just ignore it.
      }
    }
    OST << std::endl;
  }

}

