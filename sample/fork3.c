#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pthread.h>

void* thread_entry(void* p __attribute__((unused))) 
{
  printf("pthread_self()=%lu\n", pthread_self());
  sleep(1);
  return NULL;
}

int main() 
{
  pid_t p;
  if (fork() == 0) {
    printf("hello, parent!\n");  
    return 1;
  }
  if ((p = fork()) == 0) {
    pthread_t t;
    pthread_create(&t, NULL, thread_entry, 0);
    pause();
    pthread_join(t, NULL);
    return 1;
  }
  if (fork() == 0) {
    pthread_t t;
    pthread_create(&t, NULL, thread_entry, 0);
    volatile int* a = 0;
    *a = 1; // SEGV
    pthread_join(t, NULL);
    return 1;
  }
  if (fork() == 0) {
    execlp("/bin/echo", "echo", "-n", NULL);
    return 1;
  }
  if (fork() == 0) {
    pthread_t t;
    pthread_create(&t, NULL, thread_entry, 0);
    execlp("./hello", "hello", NULL);
    return 1;
  }
  kill(p, SIGTERM);

  pthread_t t;
  pthread_create(&t, NULL, thread_entry, 0);
  sleep(6);

  pthread_join(t, NULL);
  while(waitpid(-1, 0, 0) != -1);
  return 0;
}

