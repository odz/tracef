// $Id: opt.h,v 1.14 2007/09/22 22:03:08 sato Exp $

#ifndef OPT_H_
#define OPT_H_

#include <map>
#include <set>
#include <vector>
#include <string>
#include <iosfwd>
#include <boost/utility.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/program_options/options_description.hpp>

#include <unistd.h>
#include <sys/types.h>

namespace hoge {
  static const pid_t DONT_ATTACH = -1;

  class cl_options : boost::noncopyable {
  public:
    cl_options();
    bool parse_argv(int ac, char* av[], 
                    std::vector<std::string>& leftover);
    void usage() const;
    void version() const;

  public:
    bool output_per_pid_;
    bool trace_child_;
    bool read_synthetic_syms_;
    bool demangle_;
    bool print_pid_;
    bool print_time_;
    bool print_time_usec_;
    bool print_func_argument_;
    bool print_func_argument_value_;
    bool print_func_addr_;
    bool print_file_line_;
    bool print_call_tree_; // rather than list
    int  offset_;
    bool dup_fd_;

    pid_t pid_;
    std::set<std::string> exclude_syms_;
    std::ostream& ost(pid_t pid) const;
    int get_fd() const { return fd_; }

  private:
    void check_consistency(const std::vector<std::string>& leftover) const;
    std::pair<std::string, std::string> parser(const std::string& s);
    void open_file();
    void open_pid_file(pid_t pid) const;
    void do_open_file(const std::string& filename, pid_t pid) const;
 
  private:
    std::string filename_;
    mutable std::map<pid_t, boost::shared_ptr<std::ostream> > ostmap_;
#if defined(HAVE_EXT_STDIO_FILEBUF)
    mutable std::set<boost::shared_ptr<std::filebuf> > fbuf_;
    mutable int fd_; // first ost's fd
#endif

    boost::program_options::options_description visible_desc_;
    std::vector<std::string> tmp_;
    bool input_; // quick dirty hack..
  };
}

#endif

