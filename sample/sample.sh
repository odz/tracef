#!/bin/sh

HT=../src/tracef
if [ ! -x $HT ] ; then
  echo "error: $HT not found."
  exit
fi

if [ ! -d "logs/" ] ; then
  echo "error: logs/ not found."
  exit
fi

ulimit -c 0
make CFLAGS= CXXFLAGS= clean all

v="-v"
if [ `arch` == "x86_64" ] ; then
  v=""
fi  

rm -f logs/*.log logs/thread_ff.log.*

echo
echo "tracing hello... (flat output)"
$HT --dup-fd --plt -lA -o logs/hello_flat.log ./hello
echo "tracing hello... (tree output)"
$HT --dup-fd --plt -lTA -o logs/hello_tree.log ./hello
echo "tracing qsort..."
$HT --dup-fd --plt -lT -o logs/qsort.log ./qsort
echo "tracing exec..."
$HT --dup-fd --plt -flATu $v -o logs/exec.log ./exec 0 5
echo "tracing thread..."
$HT --dup-fd --plt -flT -o logs/thread.log ./thread
echo "tracing thread... (w/ --ff)"
$HT --plt -flT --ff -o logs/thread_ff.log ./thread > /dev/null
echo "tracing fork..."
$HT --dup-fd --plt -flATu -o logs/fork.log ./fork
echo "tracing fork2... (fork + exec + segv)"
$HT --dup-fd --plt -flATu -o logs/fork2.log ./fork2
echo "tracing fork3... (fork2 + multi-threading)"
$HT --dup-fd --plt -flATu -o logs/fork3.log ./fork3
echo "tracing recursion..."
$HT --dup-fd -lAT $v -o logs/recursion.log ./recursion
echo "tracing recursion... (w/ tail-recursion optimization)"
$HT --dup-fd -lAT $v -o logs/recursion_opt.log ./recursion_opt
echo "tracing mutual_recursion..."
$HT --dup-fd -lAT $v -o logs/mutual_recursion.log ./mutual_recursion
echo "tracing mutual_recursion... (w/ tail-recursion optimization)"
$HT --dup-fd -lAT $v -o logs/mutual_recursion_opt.log ./mutual_recursion_opt
echo "tracing throw..."
$HT --dup-fd --plt -ClAT $v -o logs/throw.log ./throw
echo "tracing throw2..."
$HT --dup-fd --plt -ClAT $v -o logs/throw2.log ./throw2
echo "tracing throw3 (no --plt)..."
$HT --dup-fd -ClAT $v -o logs/throw3_try1.log ./throw3
echo "tracing throw3 (no -T)..."
$HT --dup-fd --plt -ClA $v -o logs/throw3_try2.log ./throw3
echo "tracing before_main..."
$HT --dup-fd --plt -CT -o logs/before_main.log ./before_main
echo "tracing before_main2..."
$HT --dup-fd --plt -ClAT -o logs/before_main2.log ./before_main2
echo "tracing 'stripped' hello..."
$HT --dup-fd --plt -flAT $v -o logs/hello_strip.log ./hello_strip
echo "tracing 'PIE' hello..."
$HT --dup-fd --plt -flAT $v -o logs/hello_pie.log ./hello_pie
echo "tracing 'stripped PIE' hello..."
$HT --dup-fd --plt -flAT $v -o logs/hello_pie_strip.log ./hello_pie_strip
echo "tracing hard_to_find_ret..."
$HT --dup-fd --plt -flAT $v -o logs/hard_to_find_ret.log ./hard_to_find_ret
echo "tracing hard_to_find_ret_opt..."
$HT --dup-fd --plt -flAT $v -o logs/hard_to_find_ret_opt.log ./hard_to_find_ret_opt
echo "tracing hard_to_find_ret_opt... (w/ -X option)"
$HT --dup-fd --plt -flAT $v -X sw -X sw2 -o logs/hard_to_find_ret_opt_X.log ./hard_to_find_ret_opt

echo ; echo "result:"
ls -al logs/*.log logs/thread_ff.log.*


