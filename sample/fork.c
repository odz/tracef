#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

int main() 
{
  if (fork() == 0) {
    printf("hello world\n");  
    return 1;
  }
  return 0;
}

