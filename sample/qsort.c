#include <stdlib.h>

int cmp(const void* a, const void* b)
{
  return (*(const int*)a) < (*(const int*)b); 
}

int main() 
{
  int array[] = {1,3,2,4};
  qsort(array, 5, sizeof(int), cmp);
  return array[0];
}


