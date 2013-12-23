#include <stdio.h>
int odd(unsigned int n);
 
int even(unsigned int n) 
{
  if (n == 0) return 1;
  if (n == 1) return 0;
  return odd(n - 1);
}

int odd(unsigned int n) 
{
  if (n == 0) return 0;
  if (n == 1) return 1;
  return even(n - 1);
}

int main() 
{
  printf("4 is %s\n", even(4) ? "even" : "odd");
  return 0;
}



