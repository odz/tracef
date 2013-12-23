// $Id: main.cpp,v 1.50 2007/09/24 07:57:14 sato Exp $ 
#include "main.h"

#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <cerrno>
#include <ctime>

#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>

#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>

#include "opt.h"
#include "trace.h"    // traceme()
#include "process.h"
#include "printer.h"

namespace {

  pid_t attach_child(pid_t pid) 
  {
    hoge::tracer::attach(pid);
    return pid;
  }

  pid_t spawn_child(const std::vector<std::string>& args, int fd) 
  {
    assert(!args.empty());

    pid_t p = ::fork();
    if (p == -1) {
      THROW_ERRNO(fork);
    } else if (p == 0) {
      const char** argv 
        = (const char**) std::malloc(sizeof(char*) * (args.size() + 1));
      if (argv) {
        std::vector<std::string>::size_type i;
        for(i = 0; i < args.size(); ++i) {
          argv[i] = args[i].c_str();
        }
        argv[i] = NULL;
        hoge::tracer::traceme();
        ::setenv("LD_BIND_NOW", "1", 1);
        if (fd != -1) {
          // XXX: TODO: setvbuf() ??
          ::close(STDOUT_FILENO); ::dup2(fd, STDOUT_FILENO);
          ::close(STDERR_FILENO); ::dup2(fd, STDERR_FILENO);
        }
        ::execvp(argv[0], const_cast<char* const*>(argv));
        ::perror("execvp");
      }
      ::_exit(-1);
    }
    return p;
  }

  void uninstall_signalhandler()
  {
    for(std::size_t i = 0; i < HT_LENGTHOF(hoge::signals); ++i) {
      if (::signal(hoge::signals[i], SIG_DFL) < 0) {
        THROW_ERRNO("signal");
      }
    }
  }

  void sig_handler(int, siginfo_t *, void *)
  {
    hoge::signaled = HT_SIGNALED;
    hoge::process::stop_all(); // async-signal-safe
    uninstall_signalhandler(); // ditto.
  }

  void install_signalhandler()
  {
    struct sigaction sa;

    for(std::size_t i = 0; i < HT_LENGTHOF(hoge::signals); ++i) {
      std::memset(&sa, 0, sizeof(sa));
      sa.sa_handler = NULL;
      sa.sa_sigaction = sig_handler;
      sa.sa_flags = SA_SIGINFO | SA_RESTART;
      ::sigemptyset(&sa.sa_mask);
      for(std::size_t j = 0; j < HT_LENGTHOF(hoge::signals); ++j) {
        if (i != j) {
          ::sigaddset(&sa.sa_mask, hoge::signals[j]);
        }
      }
      if (::sigaction(hoge::signals[i], &sa, NULL) < 0) {
        THROW_ERRNO("sigaction");
      }
    }
  }

  void process_event(boost::shared_ptr<const hoge::cl_options> opts, 
                     boost::shared_ptr<hoge::printer> pr)
  {
    hoge::pprocess current_proc; // optimization 
    do {
      current_proc = hoge::process::wait_for_debugee(pr, opts);
      if (! current_proc) { continue; }
      if (hoge::signaled == HT_DETACH_OK) {
        current_proc->untrace();
        current_proc.reset();
        continue;
      }
      current_proc->cont();
    } while (true);
  }

  bool parse_options(int argc, char** argv,
                     boost::shared_ptr<hoge::cl_options> opts,
                     std::vector<std::string>& leftover)
  {
    bool ret;
    try {
      ret = opts->parse_argv(argc, argv, leftover);
    } catch(std::logic_error& e) {
      // exception from boost::program_options
      HT_ERR << PACKAGE_NAME << ": invalid option (" 
             << e.what() 
             << ")" 
             << std::endl << std::endl;    
      opts->usage();
      return false;
    } catch(std::runtime_error& e) {
      // exception from tracef
      if (std::strlen(e.what()) > 0) {
        HT_ERR << PACKAGE_NAME 
               << ": " << e.what() 
               << std::endl << std::endl;
      }
      opts->usage();
      return false;
    }
    return ret;
  }

}

int main(int argc, char** argv) {

  // parse command line options
  boost::shared_ptr<hoge::cl_options> opts(new hoge::cl_options);
  std::vector<std::string> leftover;
  if (!parse_options(argc, argv, opts, leftover)) {
    return EXIT_FAILURE;
  }
#if defined(__i386__) || defined(__x86_64__)
  opts->exclude_syms_.insert("__i686.get_pc_thunk.bx");
  opts->exclude_syms_.insert("__i686.get_pc_thunk.cx");
#endif
  boost::shared_ptr<hoge::printer> pr(new hoge::default_printer(opts));

  try {
    pid_t child UNUSED_;

    // fork or attach process
    if (opts->pid_ == hoge::DONT_ATTACH) {
      if (opts->dup_fd_) {
        child = spawn_child(leftover, opts->get_fd());
      } else {
        child = spawn_child(leftover, -1);
      }
    } else {
      child = attach_child(opts->pid_);
    }
    install_signalhandler();

    hoge::pprocess current_proc 
      = hoge::process::wait_for_debugee(pr, opts, true);
    if (current_proc) {
      // always trace children internally, regardless of the opts_.trace_child_ flag.
      current_proc->trace_child(); 

      // read ELF symbols and setup breakpoints
      hoge::read_sym_set_bp(current_proc->get_pid(), opts, *current_proc);
      pr->symbol_info_printer_(*current_proc);

      // ::kill(child, SIGKILL); // debug: read syms then quit.
      current_proc->cont();

      // main loop
      process_event(opts, pr); 
    }

  } catch(std::runtime_error& e) {
    HT_ERR << PACKAGE_NAME << ": " << e.what() << std::endl;
    return EXIT_FAILURE;

  } catch(std::string& finish) {
    HT_ERR << PACKAGE_NAME << ": " << finish << std::endl;
  }
  return EXIT_SUCCESS;
}

namespace hoge {
  sig_atomic_t signaled = HT_NOT_SIGNALED;

  void throw_errno(const char* fn, const char* file, int line)
  {
    char buf[128] = {0};
    // glibc's strerror_r never write to 'buf'? (-lpthread needed??)
    const char* bufp = ::strerror_r(errno, buf, sizeof(buf) - 1);
    std::stringstream ss_;
    ss_ << fn << ": " << bufp << " (" << file << ":" << line << ")";    
    throw std::runtime_error(ss_.str());
  }
}


