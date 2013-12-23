#include <stdio.h>
#include <stdlib.h>

int cmp2(const void* a, const void* b)
{
  throw 1; // throw will go through DSO
  return (*(const int*)a) < (*(const int*)b); 
}

int main() 
{
  int array[] = {1,3,2,4};
  try {
    qsort(array, 5, sizeof(int), cmp2);

    // when you throw exception from DSO (or callback function called by 
    // DSO -- this case) AND catch it in your executable binary, you must
    // turn off either --plt or -T option.
    // Or, the process will abort regardless of the catch in main()
    // due to tracef's PLT-tweaking..... 

  } catch(...) {}
  return array[0];
}
