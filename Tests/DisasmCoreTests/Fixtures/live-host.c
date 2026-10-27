extern int debug_helper(int);

static long syscall3(long number, long a, long b, long c) {
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x8 __asm__("x8") = number;
    __asm__ volatile("svc 0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory");
    return x0;
}

// A freestanding Android ARM64 host keeps device tests independent of an installed NDK/sysroot.
__attribute__((noreturn)) void _start(void) {
    for (int i = 0; i < 3000; ++i) {
        debug_helper(21);
        syscall3(64, 1, (long)"tick\n", 5);
        long delay[2] = {0, 20000000};
        syscall3(101, (long)delay, 0, 0);
    }
    syscall3(94, 0, 0, 0);
    __builtin_unreachable();
}
