#include <stdio.h>
#include <pthread.h>

void* thread_entry(void* p __attribute__((unused))) 
{
  printf("pthread_self()=%lu\n", pthread_self());
  return NULL;
}

int main() 
{
  pthread_t t;
  pthread_create(&t, NULL, thread_entry, 0);
  pthread_join(t, NULL);
  return 0;
}
