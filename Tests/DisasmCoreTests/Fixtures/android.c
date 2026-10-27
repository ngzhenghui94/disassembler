extern int puts(const char *);
extern int printf(const char *, ...);
extern int external_counter;

int read_counter(void) { return external_counter; }

#ifdef MIXED_ARM
__attribute__((target("arm")))
#endif
__attribute__((noinline, visibility("hidden"))) int helper(int x) {
    return x * 2 + 1;
}

int Java_com_example_Test_value(void *env, void *object, int x) {
    puts("hello-from-android");
    printf("android-value=%d\n", x);
    return helper(x) + 7;
}
