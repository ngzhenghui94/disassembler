volatile int debug_counter;

__attribute__((noinline)) int debug_helper(int value) {
    debug_counter = value * 2 + 1;
    return debug_counter;
}
