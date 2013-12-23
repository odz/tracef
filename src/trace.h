// $Id: trace.h,v 1.22 2007/09/16 19:51:49 sato Exp $

#ifndef TRACER_H_
#define TRACER_H_

#include <csignal>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ptrace.h>

// #include <asm/user.h>
struct user_regs_struct;

#include <boost/utility.hpp>

#if defined(__i386__) || defined(__x86_64__)
  #define BREAKPOINT_INSN      0xCC
  #define BREAKPOINT_INSN_LEN     1
  #if defined(__i386__) 
    #define SP_     esp
    #define PC_     eip
    #define RETVAL_ eax
  #else
    // x86_64
    #define SP_     rsp
    #define PC_     rip
    #define RETVAL_ rax
  #endif  
#else
  #error unknown arch
#endif

namespace hoge {
  class tracer : boost::noncopyable  {
  public:
    explicit tracer(pid_t pid);

    static void attach(pid_t pid);
    static void traceme();
    void set_trace_opt(bool trace_fork, bool trace_clone);

    void cont();
    void single_step(); 
    void detach();
    void send_signal(int signo);  // and cont

    void offset_pc(off_t v);
    void set_pc(uintptr_t pc);

    void break_at(uintptr_t addr)
    {
      // XXX: bp insn is not always single-byte.
      set_byte(addr, BREAKPOINT_INSN);
    }
    
    void set_byte(uintptr_t addr, sinsn_t insn);
    void set_word(uintptr_t addr, uintptr_t word);
    sinsn_t get_byte(uintptr_t addr) const;
    uintptr_t get_word(uintptr_t addr) const;

    void set_regs(const user_regs_struct& regs);
    void get_regs(user_regs_struct& regs) const;
    uintptr_t get_pc(void) const;
    uintptr_t get_sp(void) const;

    // returns newly created process/thread's pid/lwp-id
    uintptr_t get_eventmsg() const; 
    void get_siginfo(siginfo_t& si) const; 

    static bool is_fork_event(int wait_status);
    static bool is_clone_event(int wait_status);
    static bool is_exec_event(int wait_status);

    static
    bool is_no_event(int wait_status)
    {
      int event = (wait_status >> 16) & 0xffffU;
      return (event == 0x0); // warn: undocumented
    }

  private:
    const pid_t pid_;
  };
}

#endif

