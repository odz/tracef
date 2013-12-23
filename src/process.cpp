// $Id: process.cpp,v 1.51 2007/09/24 07:57:14 sato Exp $

#include "main.h"

#include <csignal>
#include <sys/wait.h>
#include <ext/functional>
#include <boost/bind.hpp>

#include "process.h"
#include "printer.h"
#include "xelf.h"

#ifdef DEBUG
namespace {
  std::stringstream dbg;
  // std::ostream& dbg = std::cerr;
}
#endif

// from binutils/include/demangle.h
#define DMGL_PARAMS      (1 << 0)   /* Include function args */
#define DMGL_ANSI        (1 << 1)   /* Include const, volatile, etc */
#define DMGL_VERBOSE     (1 << 3)   /* Include implementation details.  */
#define DMGL_TYPES       (1 << 4)   /* Also try to demangle type encodings. */
#define DMGL_RET_POSTFIX (1 << 5)   /* Print function return types (when
                                       present) after function signature */

// in /usr/lib/libiberty.a
extern "C" char* cplus_demangle(const char* mangled, int options);

namespace {

  // helper for signal-safety
  class mask : boost::noncopyable {
  public:
    mask() {
      ::sigset_t s;
      ::sigemptyset(&s);
      for(std::size_t i = 0; i < HT_LENGTHOF(hoge::signals); ++i) {
        ::sigaddset(&s, hoge::signals[i]);
      }
      ::sigprocmask(SIG_BLOCK, &s, &oldset_);
    }
    ~mask() throw() {
      ::sigprocmask(SIG_SETMASK, &oldset_, NULL);
    }
  private:
    ::sigset_t oldset_;
  };

  std::string demangle_symbol(const std::string& sym) 
  {
    std::string::size_type l = sym.length();
    if (l > 4 && sym.find("@plt") == l - 4) {
      // cplus_demangle() can't handle 'foobar@plt' symbols
      return demangle_symbol(sym.substr(0, sym.length() - 4)) + "@plt";
    } else {
      char* dem = ::cplus_demangle(sym.c_str(), DMGL_PARAMS | DMGL_ANSI);
      if (dem) {
        std::string ret;
        try { ret = dem; } catch(...) {}
        std::free(dem);
        return ret;
      }
    }
    return sym;
  }

  const char* str_trace_event(hoge::trace_event ev) 
  {
    using namespace hoge;
    switch(ev) {
    case EV_TRACING:           return "EV_TRACING";
    case EV_EXIT:              return "EV_EXIT";
    case EV_SIG_EXIT:          return "EV_SIG_EXIT";
    case EV_FORK:              return "EV_FORK";
    case EV_CLONE:             return "EV_CLONE"; 
    case EV_EXEC:              return "EV_EXEC";
    case EV_SIGSTOP:           return "EV_SIGSTOP";
    case EV_SIGNALED:          return "EV_SIGNALED";
    case EV_SIGNALED_CRITICAL: return "EV_SIGNALED_CRITICAL"; 
    case EV_NEW:               return "EV_NEW";
    case EV_UNKNOWN:           return "EV_UNKNOWN";
    }
    return "EV_???";
  }

  // waitpid(2) stuff
  bool do_wait_for_debugee(hoge::trace_event& ev, 
                           int& signo, pid_t& current_pid)
  {
    using namespace hoge;
    
    int st;
    pid_t pid = ::waitpid(-1, &st, __WALL);
    // __WALL means 'wait for processes AND threads' 

    if (pid == -1) {
      if (errno == ECHILD || errno == EINTR) {
        return false;
      } 
      THROW_ERRNO("waitpid");
    }
    if (signaled == HT_SIGNALED) {
      signaled = HT_DETACH_OK;
    }

    ev = EV_UNKNOWN;
    signo = _NSIG;
    current_pid = pid;

    if (WIFSTOPPED(st)) {
      signo = WSTOPSIG(st);
      if (signo == SIGTRAP) {
        if (tracer::is_no_event(st)) {
          ev = EV_TRACING;
        } else if (tracer::is_fork_event(st)) {
          ev = EV_FORK;
        } else if (tracer::is_clone_event(st)) {
          ev = EV_CLONE;
        } else if (tracer::is_exec_event(st)) {
          ev = EV_EXEC;
        } else {
          assert(false);
        }
      } else if (signo == SIGSEGV || signo == SIGBUS || 
                 signo == SIGILL  || signo == SIGFPE) {
        ev = EV_SIGNALED_CRITICAL;
      } else if (signo == SIGSTOP) {
        ev = EV_SIGSTOP;
      } else {
        ev = EV_SIGNALED;
      }
    } else if (WIFEXITED(st)) {
      ev = EV_EXIT;
    } else if (WIFSIGNALED(st)) {
      signo = WTERMSIG(st); 
      ev = EV_SIG_EXIT;
    }

#ifdef DEBUG
    // if (ev != EV_TRACING) 
    {
      char buf[128] = {0};
      std::snprintf(buf, sizeof(buf) - 1,
                    "%s: st=%d ev=%d(%s), pid=%d, signal=%d(%s)",
                    __FUNCTION__, st, ev,
                    str_trace_event(ev),
                    current_pid, signo,
                    (signo == _NSIG ? "_NSIG" : ::strsignal(signo)));
      dbg << buf << std::endl;
    }
#endif
    return true;
  }

  // for PLT tweaking
  uintptr_t get_GOT_addr(uintptr_t pc_PLT_top, hoge::tracer& t)
  {
#if defined(__i386__)
    uintptr_t GOT_addr  = t.get_word(pc_PLT_top + HT_PLT_OFFSET);
#elif defined(__x86_64__)
    uintptr_t GOT_addr  = t.get_word(pc_PLT_top + HT_PLT_OFFSET);
    GOT_addr &= 0xffffffffUL;
    GOT_addr += (pc_PLT_top + HT_PLT_INSN_SIZE); 
#else
    #error unknown arch
#endif
    return GOT_addr;
  }

}

namespace hoge {
  /* static */ pid_t process::tracer_pid_ = -1;
  /* static */ proc_map_t* process::procs_ = NULL; 
  /* static */ std::set<pid_t> process::pending_sigstops_; 

  __attribute__((constructor)) void init() 
  {
    hoge::process::procs_ = new proc_map_t;
  }

  __attribute__((destructor)) void wait_for_clients()
  {
    delete hoge::process::procs_;
    while(waitpid(-1, NULL, __WALL) != -1);
    // all children exited. or this process is signeled (EINTR).
  }

  void read_sym_set_bp(pid_t pid, 
                       boost::shared_ptr<const hoge::cl_options> opts, 
                       hoge::process& proc) 
  {
    try {
      if (proc.is_tracing() && proc.read_symbols()) {
        proc.set_breakpoints();
        if (opts->print_call_tree_) {
          proc.set_ret_breakpoints();
        }
      }
    } catch(std::runtime_error& e) {
      opts->ost(pid) << PACKAGE_NAME << ": " << e.what() << std::endl;
    }
  }

  process::process(pid_t pid, pid_t ppid, bool is_thr, 
                   boost::shared_ptr<hoge::printer> pr,
                   boost::shared_ptr<elf> pelf,
                   boost::shared_ptr<const cl_options> popt)
    : pid_(pid), ppid_(ppid), is_thread_(is_thr), 
      last_event_(EV_NEW), last_signal_(_NSIG), 
      pr_(pr), pelf_(pelf), opts_(popt), tracer_(pid),
      tracing_(true), call_level_(0)
  {
    if (pending_sigstops_.find(pid_) != pending_sigstops_.end()) {
      tracer_.cont();
      pending_sigstops_.erase(pid_); 
    }
    pr_->attach_info_printer_(*this);
  }

  process::~process() throw() {
    try {
      switch(get_last_event()) {
      case EV_EXIT:
      case EV_SIG_EXIT:
        break;
      default:
        // last_event_ = EV_EXIT;
        unset_breakpoints();
        unset_ret_breakpoints();
        tracer_.detach();
        tracer_.cont(); // ltrace's way
      }
    } catch (...) {}

    try {
      pr_->detach_info_printer_(*this);
    } catch (...) {}
  }

  void process::untrace()
  {
    mask m; // RAII
    int ndel UNUSED_ = procs_->erase(get_pid());
    assert(ndel == 1);
  }

  /* static */ void process::stop_all()
  {
    proc_map_t::iterator iter = procs_->begin();
    while(iter != procs_->end()) {
      iter->second->stop();
      ++iter;
    }
  }

  /* static */ pprocess 
  process::clone(pid_t pid, bool create_thread, const process& parent)
  {
    pprocess new_proc(new process(pid, 
                                  parent.get_pid(), 
                                  create_thread,
                                  parent.pr_, 
                                  parent.pelf_,
                                  parent.opts_));
    
    if (parent.tracing_ && parent.opts_->trace_child_) {
      new_proc->tracing_ = true;
    } else {
      new_proc->tracing_ = false;
    }

    if (!create_thread) {
      new_proc->call_level_     = parent.call_level_;
      new_proc->call_stack_     = parent.call_stack_;

      // copy 'return address from fork@plt'
      new_proc->plt_call_stack_ = parent.plt_call_stack_;
    }

    mask m; // RAII
    procs_->insert(std::make_pair(pid, new_proc));
    return new_proc;
  }

  /* static */ pprocess 
  process::create_first_process(pid_t pid,
                                boost::shared_ptr<printer> pr,
                                boost::shared_ptr<const cl_options> popt)
  {
    boost::shared_ptr<elf> null;
    tracer_pid_ = ::getpid(); // libc-call
    pprocess new_proc(new process(pid, tracer_pid_,
                                  false,      // non-thread
                                  pr, null, popt));
    mask m; // RAII
    procs_->insert(std::make_pair(pid, new_proc));
    return new_proc;
  }

  pid_t process::get_tracer_pid() const
  {
    return tracer_pid_;
  }

  pprocess process::create_thread(pid_t new_lwpid)
  {
    return process::clone(new_lwpid, true, *this);
  }

  pprocess process::fork_process(pid_t new_pid)
  {
    return process::clone(new_pid, false, *this);
    /* you can share pelf_, unless evecve(2) performed */ 
  }

#define DECR(lv) do { if ((lv) != 0) { --(lv); } } while(0)

  void process::adjust_call_stack_pre(uintptr_t pc)
  {
    uintptr_t s = 0x0, func = 0x0;

    // known BP?
    try { pelf_->get_byte_at(pc); } catch(...) { return; }

    // leaving function?
    if (! pelf_->is_func_addr(pc)) {
      // yes, leaving
      if (call_stack_.empty()) {
	call_level_ = 0;
      } else {
	try {
          func = pelf_->get_func_addr(pc);
	} catch(...) { return; }
        
        // excluded (-X) function?
        const std::string fn = pelf_->get_funcname(func);
        if (opts_->exclude_syms_.find(fn) != opts_->exclude_syms_.end()) {
          return;
        }

        const size_t UNUSED_ orig_cl = call_level_;
        do { 
          s = call_stack_.top(); call_stack_.pop(); 
          DECR(call_level_);
          if (orig_cl - call_level_ > 1 && s != func) { 
            // mis-indent finder for me..
            // std::fprintf(stderr, "SKIPPED %08x\n", s); std::fflush(stderr); 
          }
        } while (!call_stack_.empty() && (s != func));

      }
    }

    return;
  }

  void process::adjust_call_stack_post(uintptr_t pc)
  {
    // known BP?
    try { pelf_->get_byte_at(pc); } catch(...) { return; }

    // entering function?
    if (pelf_->is_func_addr(pc)) {
      // yes, entering

      // excluded (-X) function?
      const std::string fn = pelf_->get_funcname(pc);
      if (opts_->exclude_syms_.find(fn) != opts_->exclude_syms_.end()) {
        return;
      }

      if (! pelf_->is_noret_func_addr(pc)) {
        call_stack_.push(pc);
        ++call_level_;
      }
    }
    return;
  }

  bool process::update_status(trace_event ev, int signo)
  {
    pid_t pid = -1; // new pid or new LWP-id
    bool process_alive = true;

    last_event_ = ev;
    if (signo != _NSIG) {
      last_signal_ = signo;
    }

    switch (ev) {
    case EV_TRACING:
      if (is_process() && (!tracing_)) {
        unset_breakpoints();
        unset_ret_breakpoints();
      } else {
        uintptr_t pc = get_pc() - BREAKPOINT_INSN_LEN;
        adjust_call_stack_pre(pc);
      }
      pr_->function_info_printer_(*this);
      break;
    case EV_EXIT:
    case EV_SIG_EXIT:
      untrace();
      process_alive = false;
      break;
    case EV_FORK:
      pid = tracer_.get_eventmsg();
      fork_process(pid);
      break;
    case EV_CLONE:
      pid = tracer_.get_eventmsg();
      create_thread(pid);
      break;
    case EV_SIGNALED_CRITICAL:
      tracer_.get_siginfo(last_signal_info_);
      /* fall through */
    case EV_SIGNALED:
      pr_->signal_info_printer_(*this);
      break;
    case EV_EXEC:
      pr_->exec_info_printer_(*this);
      hoge::read_sym_set_bp(get_pid(), opts_, *this);
      pr_->symbol_info_printer_(*this);
      break;
    case EV_SIGSTOP:
    case EV_NEW:
    case EV_UNKNOWN:
      break;
    } 

    return process_alive;
  }

  /* static */ pprocess 
  process::wait_for_debugee(boost::shared_ptr<printer> pr,
                            boost::shared_ptr<const cl_options> popt,
                            bool initial /* = false */ )
  {
    int signo;
    trace_event ev;
    pid_t debugee_pid;

    if (! do_wait_for_debugee(ev, signo, debugee_pid)) {
      throw std::string("done"); // XXX
    } 

    pprocess null;
    {
      mask m; // RAII
      proc_map_t::iterator i = procs_->find(debugee_pid);
      if (i != procs_->end()) {
        pprocess proc(i->second);
        if (proc->update_status(ev, signo)) {
          return proc;
        } else {
          return null;
        }
      }
    }

    if (initial) {
      if (ev == EV_TRACING || ev == EV_SIGSTOP)
        // case 1. initial child process created (EV_TRACING)
        //                     or  
        // case 2. attached process is ready (EV_SIGSTOP)       
        return process::create_first_process(debugee_pid, pr, popt);
    } else if (ev == EV_EXIT) {
      // spawn_child() failed.
      return null;
    } else {
      if (ev == EV_SIGSTOP) {
        pending_sigstops_.insert(debugee_pid);
      }
    }

#ifdef DEBUG
    // something weird...
    dbg << "stray event " << str_trace_event(ev) << " to pid: " 
        << debugee_pid << std::endl; 
#endif
    return null;
  }

  std::string process::get_funcname(uintptr_t addr, bool demangle) const
  {
    try {
      const std::string& funcname = pelf_->get_funcname(addr);
      return demangle ? demangle_symbol(funcname) : funcname;
    } catch(...) {}
    return HT_UNKNOWN_FUNCTION;
  }

  std::string process::get_fileline(uintptr_t addr) const
  {
    try {
      return pelf_->get_fileline(addr);
    } catch(...) {}
    return HT_UNKNOWN_FILENAME;
  }

  const std::list<debug_info::func_arg>* 
  process::get_function_arguments(uintptr_t addr) const
  {
    pdebug_info d = pelf_->get_debug_info(addr, false);
    if (d) {
      return &(d->get_arg());
    }
    return NULL;
  }

  void process::set_breakpoints()
  {
    assert(pelf_);
    const std::map<uintptr_t, std::string>& syms = pelf_->get_symbols();
    __gnu_cxx::select1st<std::map<uintptr_t, std::string>::value_type> sel;
    std::for_each(syms.begin(), 
                  syms.end(), 
                  boost::bind(&tracer::break_at, 
                              &tracer_, // this
                              boost::bind(sel,_1)));
  }

  void process::set_ret_breakpoints()
  {
    assert(pelf_);
    const std::map<uintptr_t, uintptr_t>& rets = pelf_->get_ret_addrs();
    __gnu_cxx::select1st<std::map<uintptr_t, uintptr_t>::value_type> sel;
    std::for_each(rets.begin(), 
                  rets.end(), 
                  boost::bind(&tracer::break_at, 
                              &tracer_, // this
                              boost::bind(sel,_1)));
  }

  void process::unset_breakpoints()
  {
    if (!pelf_) return;

    const std::map<uintptr_t, std::string>& syms = pelf_->get_symbols();
    std::map<uintptr_t, std::string>::const_iterator iter, eiter = syms.end();
    for(iter = syms.begin(); iter != eiter; ++iter) {
      uintptr_t break_addr = iter->first;
      sinsn_t orig_insn = pelf_->get_byte_at(break_addr);
      tracer_.set_byte(break_addr, orig_insn);
    }
  }

  void process::unset_ret_breakpoints()
  {
    if (!pelf_) return;

    const std::map<uintptr_t, uintptr_t>& rets = pelf_->get_ret_addrs();
    std::map<uintptr_t, uintptr_t>::const_iterator iter, eiter = rets.end();
    for(iter = rets.begin(); iter != eiter; ++iter) {
      uintptr_t break_addr = iter->first;
      sinsn_t orig_insn = pelf_->get_byte_at(break_addr);
      tracer_.set_byte(break_addr, orig_insn);
    }
  }

  void process::cont_from_bp(uintptr_t pc)
  {
    // known BP?
    sinsn_t orig_insn;
    try {
      orig_insn = pelf_->get_byte_at(pc);
    } catch(...) { tracer_.cont(); return; }
    
    // PLT tweaking
    if (pelf_->is_PLT_enter(pc) && (! pelf_->is_cxa_throw_addr(pc))) {
      uintptr_t GOT_addr  = get_GOT_addr(pc, tracer_); 
      uintptr_t GOT_value = tracer_.get_word(GOT_addr);
      if (GOT_value != pc + HT_PLT_INSN_SIZE) {
        // NOT first PLT call.
        uintptr_t sp = tracer_.get_sp();
        uintptr_t ret_addr = tracer_.get_word(sp);
        plt_call_stack_.push(ret_addr);
        // rewrite return address
        tracer_.set_word(sp, pc + HT_PLT_INSN_SIZE);
      }
    } else if (pelf_->is_PLT_leave(pc)) {
      uintptr_t GOT_addr  = get_GOT_addr(pc - HT_PLT_INSN_SIZE, tracer_); 
      uintptr_t GOT_value = tracer_.get_word(GOT_addr);
      if (GOT_value != pc) {
        // NOT first PLT call.
        assert(! plt_call_stack_.empty());
        uintptr_t ret_addr = plt_call_stack_.top();
        plt_call_stack_.pop();
        tracer_.set_pc(ret_addr);
        tracer_.cont();
        return; // no single-step. just cont.
      }
    } 

    // recover original insn, then single step.
    tracer_.set_byte(pc, orig_insn);
    tracer_.offset_pc(-1 * BREAKPOINT_INSN_LEN);
    tracer_.single_step();
  again:
    if (::waitpid(get_pid(), NULL, __WALL) == -1) {
      if (errno == EINTR) {
        goto again;
      }
      THROW_ERRNO("waitpid");
    }

    // put breakpoint again.
    tracer_.break_at(pc);

    tracer_.cont();
    return;
  }

  void process::cont()
  {
    switch(get_last_event()) {
    case EV_TRACING:
      {
        uintptr_t pc = get_pc() - BREAKPOINT_INSN_LEN;
	cont_from_bp(pc);
        adjust_call_stack_post(pc);
      }
      return;
    case EV_SIGSTOP: 
    case EV_FORK:
    case EV_CLONE:
    case EV_EXEC:
    case EV_NEW:
    case EV_UNKNOWN:
      tracer_.cont();
      return;
    case EV_SIGNALED: 
    case EV_SIGNALED_CRITICAL: 
      tracer_.send_signal(get_last_signal()); // and cont
      return;
    case EV_EXIT:
    case EV_SIG_EXIT:
      break;
    }
    assert(false);
  }

  uintptr_t process::get_sp() const
  {
    return tracer_.get_sp();
  }  

  uintptr_t process::peek_memory(uintptr_t addr) const
  { 
    return tracer_.get_word(addr);
  }

  // returns false if .symtab is not present
  bool process::read_symbols()
  {
    pelf_.reset(new elf(get_pid())); // execve(2) may alter this symbol table.

    pelf_->collect_information(opts_->read_synthetic_syms_,
                               opts_->print_call_tree_,
                               opts_->print_file_line_,
                               opts_->print_func_argument_,
                               opts_->exclude_syms_);
    reset_call_stack();

    if (pelf_->has_sym()) {
      return true;
    }
    return false;
  }

  void process::trace_child()
  {
    tracer_.set_trace_opt(true, true); 
  }

  void process::reset_call_stack()
  {
    call_level_ = 0;
    while (!call_stack_.empty()) { call_stack_.pop(); }
    while (!plt_call_stack_.empty()) { plt_call_stack_.pop(); }
  }

  // returns _NSIG if no signals
  int process::get_last_signal() const
  {
    return last_signal_;
  } 

  bool process::is_func_addr(uintptr_t pc) const
  {
    return pelf_->is_func_addr(pc);
  }

  uintptr_t process::get_func_addr(uintptr_t addr_at_ret_insn) const
  {
    // may throw
    return pelf_->get_func_addr(addr_at_ret_insn);
  }

  std::string process::get_cmdline() const
  {
    return pelf_->get_cmdline();
  }

  void process::stop() 
  { 
    ::kill(pid_, SIGSTOP); 
  }

  const siginfo_t& process::get_last_signal_info() const 
  { 
    assert(get_last_signal() != _NSIG);
    return last_signal_info_; 
  }

  uintptr_t process::get_pc() const 
  {
    return tracer_.get_pc();
  }

  void process::get_regs(user_regs_struct& regs) const
  {
    tracer_.get_regs(regs);
  } 

  trace_event process::get_last_event() const 
  {
    return last_event_; 
  }

}
