// everyone loves exception throwing :-)

#include <stdio.h>

int c(int i) 
{
  if (i == 0) throw 0xff;
  return c(--i);
}

void b() 
{
  c(3);
}

int a()
{
  try {
    b();
  } catch(int& e) {
    return e;
  }
  return 0;
}

int main() 
{
  return a();
}

