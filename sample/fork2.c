#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/types.h>
#include <sys/wait.h>

int main() {
  pid_t p;
  if (fork() == 0) {
    printf("hello, parent!\n");  
    return 1;
  }
  if ((p = fork()) == 0) {
    pause();
    return 1;
  }
  if (fork() == 0) {
    volatile int* a = 0;
    *a = 1; // SEGV
    return 1;
  }
  if (fork() == 0) {
    execlp("/bin/echo", "echo", "-n", NULL);
    return 1;
  }
  if (fork() == 0) {
    execlp("./hello", "hello", NULL);
    return 1;
  }
  kill(p, SIGTERM);

  while(waitpid(-1, 0, 0) != -1);
  return 0;
}

