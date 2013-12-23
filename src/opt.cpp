// $Id: opt.cpp,v 1.27 2007/09/22 22:03:07 sato Exp $

#include "main.h"

#include <fstream>
#include <sstream>
#include <algorithm>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <boost/program_options/positional_options.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/preprocessor/stringize.hpp>
#include <boost/bind.hpp>
#if defined(HAVE_EXT_STDIO_FILEBUF)
  #include <ext/stdio_filebuf.h>
#endif

#include "opt.h"

namespace hoge {

  cl_options::cl_options() 
    : output_per_pid_(false),
      trace_child_(false),
      read_synthetic_syms_(false),
      demangle_(false),
      print_pid_(true),
      print_time_(false),
      print_time_usec_(false),
      print_func_argument_(false),
      print_func_argument_value_(false),
      print_func_addr_(true),
      print_file_line_(false),
      print_call_tree_(false),
      offset_(0),
      dup_fd_(false),
      pid_(DONT_ATTACH),
      fd_(-1),
      visible_desc_("Options"),
      input_(false)
  {
    namespace po = boost::program_options;
    visible_desc_.add_options()
      ("help,?", "Produce help message")
      ("version,V", "Show the version number of " PACKAGE_NAME " and exit")
      ("output,o", po::value<std::string>(), 
       "Write the trace output to the file filename rather than to stderr")
#if defined(HAVE_EXT_STDIO_FILEBUF)
      ("dup-fd",
       "Redirect target program's stdout/stderr to " PACKAGE_NAME "'s logfile "
       "specified by -o option (EXPERIMENTAL). This is incompatible with "
       "'-p pid' and '--ff' options") 
#endif
      ("ff", 
       "If the -o filename option is in effect, each processes trace is "
       "written to filename.pid where pid is the numeric process/thread "
       "id of each process"
#if defined(HAVE_EXT_STDIO_FILEBUF)
       ". This is incompatible with --dup-fd option"
#endif
      )
      ("trace-child,f", 
       "Trace child processes as they are created by currently traced "
       "processes as a result of the fork(2) or clone(2) system call")
      ("synthetic", 
       "Read synthetic symbols as well. With this option, you can trace "
       "(some) library/system calls. "
       "e.g. printf@plt, signal@plt and so on")
      ("plt", 
       "an alias for --synthetic")
      ("demangle,C",
       "Decode low-level symbol names into user-level names. This makes "
       "C++ function names readable")
      ("time,t",
       "Prefix each line of the trace with the time of day")
      ("microseconds,u",
       "Prefix each line of the trace with the time of day. "
       "The time printed will include the microseconds")
      ("arg,A",
       "Print argument name of the function (EXPERIMENTAL)")
#if defined(__i386__) 
      ("arg-val,v",
       "Print arguments value as well (EXPERIMENTAL)")
#endif
      ("call-tree,T",
       "Print call-tree. It is useful with the -o and --ff options")
      ("offset", po::value<int>(&offset_)->default_value(3),
       "Specify the number of spaces per function call. Allowed values are "
       "0 to 20 (inclusive). Default value is 3. Use this option with -T")
      ("no-pid",
       "Don't print pid")
      ("no-eip,i",
       "Don't print the instruction pointer at the time of the function call")
      ("line-numbers,l",
       "Use debugging information to find a filename and line number "
       "for the function")
      ("attach-process,p", po::value<pid_t>(&pid_),
       "Attach to the process with the process ID 'arg' and begin tracing"
#if defined(HAVE_EXT_STDIO_FILEBUF)
       ". This is incompatible with --dup-fd option"
#endif
      )
      ("exclude,X", po::value<std::vector<std::string> >(&tmp_),
       "Don't trace function matching (mangled) symbol 'arg'")
      ; 
  }

  std::ostream& cl_options::ost(pid_t pid) const
  {
    if (pid != -1 && output_per_pid_) {
      // XXX: ad-hoc optimization
      static TLS_ std::ostream* cache = NULL;
      static TLS_ pid_t cache_pid = -1;
      if (cache != NULL && cache_pid == pid) {
        return *cache;
      }

      std::map<pid_t, boost::shared_ptr<std::ostream> >::const_iterator 
        i = ostmap_.find(pid);
      if (i == ostmap_.end()) {
        open_pid_file(pid);
        return ost(pid); // recursive call
      }
      cache_pid = pid;
      cache = (i->second).get();
      return *cache;
    } else {
      // XXX: ad-hoc optimization
      static TLS_ std::ostream* cache = NULL;
      if (cache != NULL) {
        return *cache;
      }

      std::map<pid_t, boost::shared_ptr<std::ostream> >::const_iterator 
        i = ostmap_.find(-1);
      if (i == ostmap_.end()) {
        cache = &HT_ERR;
      } else {
        cache = (i->second).get();
      }
      return *cache;
    }
  }

  void cl_options::usage() const
  {
    HT_ERR << "Usage:" 
           << std::endl
           << "  % " << PACKAGE_NAME << " [option ...] command [arg ...]"
           << std::endl      
           << "  % " << PACKAGE_NAME << " [option ...] -p pid"
           << std::endl
           << visible_desc_ 
           << std::endl;
  }

  void cl_options::version() const
  {
    HT_ERR << PACKAGE_NAME << " version " << PACKAGE_VERSION << "\n"
           << "Copyright (C) 2007 SATO Yusuke <ads01002@nifty.com>.\n\n"
           << "This is free software. You may redistribute copies of "
           << "it under the terms\n"
           << "of the GNU General Public License "
           << "<http://www.gnu.org/licenses/gpl.html>.\n"
           << "There is NO warranty." << std::endl;
  }

  void cl_options::open_pid_file(pid_t pid) const
  {
    std::stringstream ss;
    ss << filename_ << "." << pid;
    do_open_file(ss.str(), pid);
  }

  void cl_options::open_file()
  {
    do_open_file(filename_, -1);
  }

  void cl_options::do_open_file(const std::string& filename, pid_t pid) const
  {
#if defined(HAVE_EXT_STDIO_FILEBUF)
    // GCC3 or later 
    int fd;
    if ((fd = ::open(filename.c_str(), 
                     O_WRONLY | O_CREAT | O_TRUNC, 0600)) == -1) {
      THROW_ERRNO(open);
    }
    boost::shared_ptr<std::filebuf> 
      fbuf(new __gnu_cxx::stdio_filebuf<char>(fd, std::ios_base::out));
    boost::shared_ptr<std::ostream> 
      ost(new std::ostream(fbuf.get()));
    if (fd_ == -1) {
      fd_ = fd;
    }
#else
    // non-GCC or GCC2
    boost::shared_ptr<std::ostream> 
      ost(new std::fstream(filename.c_str(), std::ios::out));
#endif
    if (ost->fail()) {
      THROW_STR("can't open file", filename);
    }
    ostmap_.insert(std::make_pair(pid, ost));
#if defined(HAVE_EXT_STDIO_FILEBUF)
    fbuf_.insert(fbuf);
#endif
  }

#define MUTEX_OPT(a,b)                                                  \
  THROW_STR("invalid option",                                           \
            BOOST_PP_STRINGIZE(a) " and "                               \
            BOOST_PP_STRINGIZE(b) " are mutually exclusive options") 

  void
  cl_options::check_consistency(const std::vector<std::string>& leftover) const
  {
    if ((pid_ == DONT_ATTACH) && leftover.empty()) {
      THROW_STR("invalid option", "no executable name given");
    }

    if ((pid_ != DONT_ATTACH) && (!leftover.empty())) {
      THROW_STR("invalid option", 
                "both -p pid and executable names are given");
    }

    if (pid_ != DONT_ATTACH && dup_fd_) {
      MUTEX_OPT(-p,--dup-fd);
    }

    if (dup_fd_ && output_per_pid_) {
      MUTEX_OPT(--ff,--dup-fd);
    }

    if ((filename_ == "") && output_per_pid_) {
      THROW_STR("invalid option", 
                "please specify log filename with -o");
    }

    if (offset_ < 0 || offset_ > 20) {
      THROW_STR("invalid option", 
                "offset is out of range. allowed values are 0 to 20");
    }

    // XXX: --offset w/o -T check?

    return; // consistent.
  }

  bool cl_options::parse_argv(int ac, char* av[], 
                              std::vector<std::string>& leftover)
  {
    namespace po = boost::program_options;

    po::options_description hidden_desc("");
    hidden_desc.add_options()
      ("input", po::value<std::vector<std::string> >(&leftover), 
       "input file (hidden option)")
      ("null", 
       po::value<std::vector<std::string> >(),
       "/dev/null (hidden option)")
      ;  

    po::positional_options_description p;
    p.add("input", -1 /* infinite */);

    po::options_description all_desc("");
    all_desc.add(visible_desc_).add(hidden_desc);

    po::variables_map vm;
    po::parsed_options parsed = 
      po::command_line_parser(ac, av).
      options(all_desc).
      positional(p).
      extra_parser(boost::bind(&cl_options::parser, this, _1)). 
      run(); // may throw logic_error
    po::store(parsed, vm); // ditto.
    po::notify(vm);    

    if (vm.count("version")) {
      version();
      return false;
    }

    if (vm.count("help")) {
      usage();
      return false;
    }

    if (vm.count("ff")) {
      output_per_pid_ = true;
    }
    if (vm.count("trace-child")) {
      trace_child_ = true;
    }
    if (vm.count("synthetic") || vm.count("plt")) {
      read_synthetic_syms_ = true; 
    }
    if (vm.count("demangle")) {
      demangle_ = true;
    }
    if (vm.count("time")) {
      print_time_ = true;
    }
    if (vm.count("microseconds")) {
      print_time_ = print_time_usec_ = true;
    }
    if (vm.count("arg")) {
      print_func_argument_ = true;
    }
    if (vm.count("arg-val")) {
      print_func_argument_ = true; // enable -A implicitly
      print_func_argument_value_ = true;
    }
    if (vm.count("call-tree")) {
      print_call_tree_ = true;
    }
    if (vm.count("no-pid")) {
      print_pid_ = false;
    }
    if (vm.count("no-eip")) {
      print_func_addr_ = false;
    }
    if (vm.count("line-numbers")) {
      print_file_line_ = true;
    }
    if (vm.count("dup-fd")) {
      dup_fd_ = true;
    }

    std::copy(tmp_.begin(), tmp_.end(), 
              std::inserter(exclude_syms_, exclude_syms_.begin()));

    if (vm.count("output")) {
      filename_ = vm["output"].as<std::string>();
      if (filename_ == "-") {
        filename_ = "";
      }
    } 

    if ((filename_ != "") && (!vm.count("ff"))) {
      open_file();
    }

    check_consistency(leftover); // may throw
    return true;
  }

  std::pair<std::string, std::string> 
  cl_options::parser(const std::string& s)
  {
    if (!input_) {
      if (s.find("-") == 0) {
        return make_pair(std::string(), std::string());
      } else {
        input_ = true;
      }
    } 

    // if positional token is once recognized, always return pair<"input",s>.
    // (or './a.out -X a b -X' triggers exception in run() method...)
    return std::make_pair("input", s);
  }

}
