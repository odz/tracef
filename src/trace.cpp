// $Id: trace.cpp,v 1.22 2007/09/16 19:51:49 sato Exp $

#include "main.h"

#include <string>
#include "trace.h"
#include <asm/user.h>

#ifdef DEBUG
namespace {
  std::stringstream dbg;
  // std::ostream& dbg = std::cerr;
}
#endif

// from <linux/ptrace.h>
#define PTRACE_O_TRACEFORK      0x00000002 
#define PTRACE_O_TRACECLONE     0x00000008 
#define PTRACE_O_TRACEEXEC      0x00000010
#define PTRACE_EVENT_FORK       1 
#define PTRACE_EVENT_CLONE      3 
#define PTRACE_EVENT_EXEC       4
#define PTRACE_GETSIGINFO       0x4202  // for RHEL4
#define PTRACE_GETEVENTMSG      0x4201  // for RHEL4

namespace hoge {
  tracer::tracer(pid_t pid) : pid_(pid) {}

  sinsn_t tracer::get_byte(uintptr_t addr) const
  {
    uintptr_t peek_addr = addr & ~(sizeof(long) - 1);
    uintptr_t data = ptrace((__ptrace_request)PTRACE_PEEKTEXT, pid_, (void*)peek_addr, NULL);  
    if (data == (uintptr_t)-1 && errno != 0 && errno != ESRCH) {
      THROW_ERRNO(ptrace);
    }
    for(unsigned int i = 0; i < addr - peek_addr; ++i) {
      data >>= 8;
    }

#ifdef DEBUG
    char buf[128] = {0};
    snprintf(buf, sizeof(buf) - 1, 
             "[[pid %d]] GET 0x%08lx: 0x%02lx", pid_, addr, (data & 0xff));
    dbg << buf << std::endl;
#endif  

    return data & 0xff;
  }
  
  void tracer::set_byte(uintptr_t addr, sinsn_t insn)
  {
    unsigned int i;
    uintptr_t mask, mask2;
    uintptr_t poke_addr = addr & ~(sizeof(long) - 1);
    
    uintptr_t data = ptrace((__ptrace_request)PTRACE_PEEKTEXT, pid_, (void*)poke_addr, NULL);
    if (data == (uintptr_t)-1 && errno != 0 && errno != ESRCH) {
      THROW_ERRNO(ptrace);
    }
    
    mask  = 0xffU;
    mask2 = insn;
    for(i = 0; i < addr - poke_addr; ++i) {
      mask <<= 8; mask2 <<= 8;
    }
    data &= ~mask;
    data |= mask2;
    
    if (ptrace((__ptrace_request)PTRACE_POKETEXT, pid_, (void*)poke_addr, (void*)data) == -1 && 
        errno != ESRCH) { 
      THROW_ERRNO(ptrace);
    }

#ifdef DEBUG
    char buf[128] = {0};
    snprintf(buf, sizeof(buf) - 1, 
             "[[pid %d]] SET 0x%08lx: 0x%02x", pid_, addr, insn);
    dbg << buf << std::endl;
#endif  

  }

  uintptr_t tracer::get_word(uintptr_t addr) const
  {
#if defined(WORDS_BIGENDIAN)
    assert(false);
#else
    uintptr_t ret = 0;
    if (addr % sizeof(uintptr_t) != 0) {
      // XXX: inefficient
      for(size_t i = 0; i < sizeof(uintptr_t); ++i) {
        sinsn_t b = get_byte(addr);
        ++addr;
        ret |= (static_cast<uintptr_t>(b) << (i * CHAR_BIT));  
	// explicit cast is required in LP64 env. (integer promotion is not 
	// sufficient. since sizeof int == 4, not 8)
      }
      return ret;
    } else {
      ret = ptrace((__ptrace_request)PTRACE_PEEKTEXT, pid_, (void*)addr, NULL);  
      if (ret == (uintptr_t)-1 && errno != 0 && errno != ESRCH) {
        THROW_ERRNO(ptrace);
      }
      return ret;
    }
#endif
  }

  void tracer::set_word(uintptr_t addr, uintptr_t w)
  {
#if defined(WORDS_BIGENDIAN)
    assert(false);
#else
    if (addr % sizeof(uintptr_t) != 0) {
      // XXX: inefficient
      uintptr_t mask = 0xffU;
      for(size_t i = 0; i < sizeof(w); ++i) {
        sinsn_t b = (w & mask) >> (i * CHAR_BIT);
        set_byte(addr, b);
        ++addr;
        mask <<= CHAR_BIT;
      }
    } else {
      if (ptrace((__ptrace_request)PTRACE_POKETEXT, pid_, (void*)addr, (void*)w) == -1 && 
          errno != ESRCH) { 
        THROW_ERRNO(ptrace);
      }
    }
#endif
  }

  void tracer::detach()
  {
    if (ptrace((__ptrace_request)PTRACE_DETACH, pid_, 
               1 /* ltrace style */, NULL) == -1 && errno != ESRCH) {
      THROW_ERRNO(ptrace);
    }
  }

  void tracer::send_signal(int signo) // and cont
  {
    assert(signo != SIGSTOP);
    uintptr_t tmp = signo;
    if (ptrace((__ptrace_request)PTRACE_CONT, pid_, NULL, (void*)tmp) == -1 && errno != ESRCH) {
      THROW_ERRNO(ptrace);
    }
  }

  void tracer::get_siginfo(siginfo_t& si) const
  {
    ::memset(&si, 0, sizeof(siginfo_t)); // valgrind
    if (ptrace((__ptrace_request)PTRACE_GETSIGINFO, pid_, NULL, &si) == -1 && errno != ESRCH) {
      THROW_ERRNO(ptrace);
    }
  }
 
  uintptr_t tracer::get_eventmsg() const
  {
    uintptr_t newpid = 0; // or new-lwp-id or exit-status
    if (ptrace((__ptrace_request)PTRACE_GETEVENTMSG, pid_, NULL, &newpid) == -1 && 
        errno != ESRCH) {
      THROW_ERRNO(ptrace);
    }
    return newpid;
  }

  /* static */ void tracer::traceme()
  {
    if (ptrace((__ptrace_request)PTRACE_TRACEME, (pid_t)0, NULL, NULL) == -1) {
      THROW_ERRNO(ptrace);
    }
  }

  /* static */ void tracer::attach(pid_t pid)
  {
    if (ptrace((__ptrace_request)PTRACE_ATTACH, pid, 
               1 /* ltrace style */, NULL) == -1) {
      THROW_ERRNO(ptrace);
    }
  }

  void tracer::set_trace_opt(bool trace_fork, bool trace_clone)
  {
    // we don't support vfork(2)
    if (!trace_fork && !trace_clone) return;

    unsigned long ptrace_flags = 
      (trace_fork  ? PTRACE_O_TRACEFORK  : 0) | 
      (trace_clone ? PTRACE_O_TRACECLONE : 0) |
      PTRACE_O_TRACEEXEC;

    if (ptrace((__ptrace_request)PTRACE_SETOPTIONS, pid_, NULL, (void*)ptrace_flags) == -1 && 
        errno != ESRCH) {
      THROW_ERRNO(ptrace);
    }
  }

  /* static */ bool tracer::is_fork_event(int wait_status)
  {
    int event = (wait_status >> 16) & 0xffffU;
    return (event == PTRACE_EVENT_FORK);
  }

  /* static */ bool tracer::is_clone_event(int wait_status)
  {
    int event = (wait_status >> 16) & 0xffffU;
    return (event == PTRACE_EVENT_CLONE);
  }

  /* static */ bool tracer::is_exec_event(int wait_status)
  {
    int event = (wait_status >> 16) & 0xffffU;
    return (event == PTRACE_EVENT_EXEC);
  }

  void tracer::cont() 
  {
    if (ptrace((__ptrace_request)PTRACE_CONT, pid_, NULL, NULL) == -1 && 
        errno != ESRCH) {
      THROW_ERRNO(ptrace);
    }
  }
  void tracer::single_step() 
  {
    if (ptrace((__ptrace_request)PTRACE_SINGLESTEP, pid_, NULL, NULL) == -1 && 
        errno != ESRCH) {
      THROW_ERRNO(ptrace);
    }
  }

  void tracer::offset_pc(off_t v)
  {
    user_regs_struct regs;
    get_regs(regs);
    regs.PC_ += v;
    set_regs(regs);
  }

  void tracer::set_pc(uintptr_t pc)
  {
    user_regs_struct regs;
    get_regs(regs);
    regs.PC_ = pc;
    set_regs(regs);
  }

  void tracer::set_regs(const user_regs_struct& regs)
  {
    if (ptrace((__ptrace_request)PTRACE_SETREGS, pid_, NULL, &regs) == -1 && errno != ESRCH) {
      THROW_ERRNO(ptrace);
    }
  }

  void tracer::get_regs(user_regs_struct& regs) const
  {
    ::memset(&regs, 0, sizeof(user_regs_struct)); // valgrind
    if (ptrace((__ptrace_request)PTRACE_GETREGS, pid_, NULL, &regs) == -1 && errno != ESRCH) {
      THROW_ERRNO(ptrace);
    }
  }  

  uintptr_t tracer::get_pc(void) const
  {
    user_regs_struct regs;
    get_regs(regs);
    return regs.PC_;
  }  

  uintptr_t tracer::get_sp(void) const
  {
    user_regs_struct regs;
    get_regs(regs);
    return regs.SP_;
  }  

}
