// $Id: printer.h,v 1.10 2007/09/22 09:32:39 sato Exp $
#ifndef PRINTER_H_
#define PRINTER_H_

#include <iosfwd>
#include <boost/function.hpp>
#include "opt.h"

namespace hoge {

  class printer : boost::noncopyable {
  public:
    typedef boost::function<void (hoge::process&)> process_printer_t;
    printer(process_printer_t attach_info_printer,
            process_printer_t detach_info_printer,
            process_printer_t function_info_printer,
            process_printer_t signal_info_printer,
            process_printer_t exec_info_printer,
            process_printer_t symbol_info_printer);
    process_printer_t attach_info_printer_;
    process_printer_t detach_info_printer_;
    process_printer_t function_info_printer_;
    process_printer_t signal_info_printer_;
    process_printer_t exec_info_printer_;
    process_printer_t symbol_info_printer_;
  };

  class default_printer : public printer {
  public:
    explicit default_printer(boost::shared_ptr<const cl_options> opts); 

  private:
    void print_attach_info(hoge::process& current_proc); 
    void print_detach_info(hoge::process& current_proc); 
    void print_signal_info(hoge::process& current_proc);
    void print_exec_info(hoge::process& current_proc);
    void print_function_info(hoge::process& current_proc); 
    void print_symbol_info(hoge::process& current_proc); 
    boost::shared_ptr<const cl_options> opts_; 
  };
}

#endif


