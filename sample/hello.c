#include <stdio.h>

void my_func_2()
{
  puts("hello, world!");
}

void my_func_1()
{
  my_func_2();
}

int main(int argc, char** argv) 
{
  my_func_1();
  fflush(stdout);
  return 0;
}
