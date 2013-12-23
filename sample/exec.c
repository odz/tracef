#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char** argv) 
{
  if (argc != 3) return 0; /* usage: ./a.out 0 N */

  int accum = atoi(argv[1]);
  int n = atoi(argv[2]);

  if (n == 0) {
    printf("answer: %d\n", accum);
    return accum;
  }

  char p[32] = {0}, q[32] = {0};
  snprintf(p, 31, "%d", accum + n);
  snprintf(q, 31, "%d", n - 1);

  execlp("/proc/self/exe", "exe", p, q, NULL);
  return -1;
}

