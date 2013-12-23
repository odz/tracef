myflags=-g -O0 -Wall -W -Wno-unused
myoptflags=-g -O1 -foptimize-sibling-calls -Wall -W -Wno-unused

AM_CXXFLAGS=${myflags}
AM_CFLAGS=${myflags}
LIBS=

bin_PROGRAMS=exec fork fork2 fork3 hello mutual_recursion mutual_recursion_opt qsort recursion recursion_opt thread throw throw2 throw3 \
before_main before_main2 \
hello_pie hello_strip hello_pie_strip \
hard_to_find_ret hard_to_find_ret_opt

exec_SOURCES=exec.c

fork_SOURCES=fork.c

fork2_SOURCES=fork2.c

fork3_SOURCES=fork3.c
fork3_LDADD=-lpthread

hello_SOURCES=hello.c

mutual_recursion_SOURCES=mutual_recursion.c

mutual_recursion_opt_SOURCES=mutual_recursion.c
mutual_recursion_opt_CFLAGS=${myoptflags}

qsort_SOURCES=qsort.c

recursion_SOURCES=recursion.c

recursion_opt_SOURCES=recursion.c
recursion_opt_CFLAGS=${myoptflags}

thread_SOURCES=thread.c
thread_LDADD=-lpthread

throw_SOURCES=throw.cpp
throw2_SOURCES=throw2.cpp
throw3_SOURCES=throw3.cpp
before_main_SOURCES=before_main.cpp
before_main2_SOURCES=before_main2.cpp

hello_pie_SOURCES=hello.c
hello_pie_CFLAGS=${myflags} -fPIE
hello_pie_LDFLAGS=-pie

hello_strip_SOURCES=hello.c
hello_strip_LDFLAGS=-s

hello_pie_strip_SOURCES=hello.c
hello_pie_strip_CFLAGS=${myflags} -fPIE
hello_pie_strip_LDFLAGS=-pie -s

hard_to_find_ret_SOURCES=hard_to_find_ret.c

hard_to_find_ret_opt_SOURCES=hard_to_find_ret.c
hard_to_find_ret_opt_CFLAGS=-g -O2

EXTRA_DIST=sample.sh \
logs/exec.log \
logs/fork.log \
logs/fork2.log \
logs/fork3.log \
logs/hello_flat.log \
logs/hello_tree.log \
logs/hello_pie.log \
logs/hello_strip.log \
logs/hello_pie_strip.log \
logs/mutual_recursion.log \
logs/mutual_recursion_opt.log \
logs/qsort.log \
logs/recursion.log \
logs/recursion_opt.log \
logs/thread.log \
logs/throw.log \
logs/throw2.log \
logs/throw3_try1.log \
logs/throw3_try2.log \
logs/before_main.log \
logs/before_main2.log \
logs/hard_to_find_ret.log \
logs/hard_to_find_ret_opt.log \
logs/hard_to_find_ret_opt_X.log \
logs/mt-daapd-0.2.4.log.22284  \
logs/mt-daapd-0.2.4.log.22285  \
logs/mt-daapd-0.2.4.log.22286  \
logs/mt-daapd-0.2.4.log.22287  \
logs/mt-daapd-0.2.4.log.22288  \
logs/mt-daapd-0.2.4.log.22289

