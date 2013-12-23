#include <stdio.h>

int sum(int n) 
{
  return n == 0 ? 0 : n + sum(n - 1);
}

int main() 
{
  int s = sum(10);
  printf("sum(10) = %d\n", s);
  fflush(stdout);
  return s;
}

