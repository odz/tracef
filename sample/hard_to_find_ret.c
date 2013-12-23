#include <sys/types.h>
#include <unistd.h>

int sw(int a) {
  switch(a) {
  case 1:
    return 2;
  case 2:
    return 1;
  case 3:
  default:
    break;
  }
  return getpid();
}

__attribute__((noreturn)) 
void my_abort() { 
  _exit(123);
}

int sw2(int a) {
  switch(a) {
  case 0:
    my_abort();
  case 1:
    return 2;
  case 2:
    return getpid();
  default:
    break;
  }
  return 1;
}

int foo(int argc) {
  volatile int a = 0;

  sw(argc + 2); // known bug: mis-indent
  sw(argc + 2); // known bug: mis-indent
  sw(argc + 2); // known bug: mis-indent
  sw2(argc + 1);  // known bug: mis-indent
  sw2(argc + 1);  // known bug: mis-indent
  sw2(argc + 1);  // known bug: mis-indent

  // force no-inline
  return a;
}

int main(int argc, char** argv) {
  int i;

  if (argc != 1) return 0;
  foo(argc);

  for(i = 0; i < 5; ++i) {
    sw(-1); // known bug: mis-indent 
  }
  sw2(argc - 1); // will exit

  return 0;
}

  

