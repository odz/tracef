// $Id: process.h,v 1.35 2007/09/22 18:20:11 sato Exp $

#ifndef PROCESS_H_
#define PROCESS_H_

#include <set>
#include <map>
#include <stack>
#include <string>

#include <unistd.h>
#include <sys/types.h>

#include <boost/utility.hpp>
#include <boost/function.hpp>
#include <boost/shared_ptr.hpp>

#include "trace.h"
#include "opt.h"
#include "xelf.h"

namespace hoge {

  enum trace_event {
    EV_TRACING = 0,
    EV_EXIT,
    EV_SIG_EXIT,
    EV_FORK,
    EV_CLONE,
    EV_EXEC,
    EV_SIGSTOP,
    EV_SIGNALED,
    EV_SIGNALED_CRITICAL, 
    EV_NEW, /* just created */
    EV_UNKNOWN,
  };

  typedef boost::shared_ptr<class process> pprocess;
  typedef std::map<pid_t, pprocess> proc_map_t;

  class printer;
  class process : boost::noncopyable {
  public:
    // returns current process or current thread
    static pprocess 
    wait_for_debugee(boost::shared_ptr<printer> pr,
                     boost::shared_ptr<const cl_options> popt,
                     bool initial = false);

    pid_t get_pid()    const { return pid_; }
    pid_t get_ppid()   const { return ppid_; }
    bool  is_thread()  const { return is_thread_; }
    bool  is_process() const { return !is_thread(); }
    bool  is_tracing() const { return tracing_; }
    std::string get_cmdline() const;
    pid_t get_tracer_pid() const;

    bool read_symbols();
    void trace_child();

    void set_breakpoints();
    void set_ret_breakpoints();
    void unset_breakpoints();
    void unset_ret_breakpoints();

    void cont();
    void stop(); // async-signal-safe
    static void stop_all();  // (maybe) async-signal-safe
    void untrace();

    trace_event get_last_event() const; 
    int get_last_signal() const;
    const siginfo_t& get_last_signal_info() const; 

    std::string get_funcname(uintptr_t addr, bool demangle) const;
    std::string get_fileline(uintptr_t addr) const;
    const std::list<debug_info::func_arg>* 
      get_function_arguments(uintptr_t addr) const;

    uintptr_t get_pc() const;
    uintptr_t get_sp() const; 
    void get_regs(user_regs_struct& regs) const;
    uintptr_t peek_memory(uintptr_t addr) const;  

    bool is_func_addr(uintptr_t pc) const;
    uintptr_t get_func_addr(uintptr_t addr_at_ret_insn) const;
    size_t get_call_level() const { return call_level_; }

    ~process() throw();

  private:
    pprocess create_thread(pid_t new_lwpid);
    pprocess fork_process(pid_t new_pid);

    /* helper for create_thread/fork_process */
    static pprocess clone(pid_t pid, 
                          bool create_thread, 
                          const process& parent);

    /* factory */
    static pprocess 
    create_first_process(pid_t new_pid,
                         boost::shared_ptr<printer> pr_,
                         boost::shared_ptr<const cl_options> popt);

    /* private ctor */ 
    process(pid_t pid, pid_t ppid, bool is_thr, 
            boost::shared_ptr<hoge::printer> pr,
            boost::shared_ptr<elf> pelf,
            boost::shared_ptr<const cl_options> popt);

    void cont_from_bp(uintptr_t pc);
    bool update_status(trace_event ev, int signo);
    void adjust_call_stack_pre(uintptr_t pc);
    void adjust_call_stack_post(uintptr_t pc);
    void reset_call_stack();

  private:
    const pid_t pid_, ppid_;
    const bool is_thread_;

    trace_event last_event_;
    int last_signal_;
    siginfo_t last_signal_info_;

    boost::shared_ptr<printer> pr_;
    boost::shared_ptr<elf> pelf_;
    boost::shared_ptr<const cl_options> opts_;
    tracer tracer_;

    bool tracing_;
    size_t call_level_;
    std::stack<uintptr_t> call_stack_;
    std::stack<uintptr_t> plt_call_stack_;

  private:
    /* static members */
    static pid_t tracer_pid_;
    static proc_map_t* procs_;                
    static std::set<pid_t> pending_sigstops_; /* warn: static initialization */ 

    friend void init();
    friend void wait_for_clients(); // fini
  };

  void read_sym_set_bp(pid_t pid, 
                       boost::shared_ptr<const hoge::cl_options> opts, 
                       hoge::process& proc) ;
}

#endif
