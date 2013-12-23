#include <cstdio>
#include <cstddef>

// 1. you can trace foo(), bar(), baz() call below main().

int foo() { return 1; }
int g = foo();

struct bar {
  bar() {}
  ~bar() throw() {}
} g2;

__attribute__((constructor))
void baz() {}

// 2. but you can't trace strSum_<> since it's not a function. 

template<const char* S, std::size_t L, std::size_t N = 0>
struct strSum_ {
  static const unsigned long value;
};

// __runtime__ computation of 'value'
template<const char* S, std::size_t L, std::size_t N>
const unsigned long strSum_<S, L, N>::value = S[N] + strSum_<S, L, N + 1>::value;

template<const char* S, std::size_t L>
struct strSum_<S, L, L> {
  static const unsigned long value = 0;
};

// main

template<typename T, std::size_t L> char (&lengthof_helper_(T(&)[L]))[L];
#define LENGTHOF(array) sizeof(lengthof_helper_(array))
// http://www.thescripts.com/forum/thread156880.html

extern const char s[] = "C++0x"; // external linkage 
int main() {
  return (int) strSum_<s, LENGTHOF(s) - 1>::value;
}
