#include <stdint.h>
#include <stdio.h>

int main() {
  __int128_t x = 1;
  __int128_t y = 1;

  if (x == y) {
    return 1;
  }
}
