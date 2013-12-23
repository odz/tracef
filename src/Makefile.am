#AM_CXXFLAGS=-fstack-protector --param=ssp-buffer-size=4 -Wp,-D_FORTIFY_SOURCE=2 -march=native
#AM_LDFLAGS=-Wl,-z,relro -Wl,-z,now

bin_PROGRAMS=tracef
tracef_SOURCES=ftrace/prototype.cpp main.cpp opt.cpp printer.cpp process.cpp trace.cpp xelf.cpp
noinst_HEADERS=ftrace/prototype.h main.h opt.h printer.h process.h trace.h xelf.h signalent.h
LIBS=-ldwarf -lelf -lbfd -liberty -lopcodes -lboost_program_options

