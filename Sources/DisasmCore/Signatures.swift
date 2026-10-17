/// Argument counts of common C library and runtime functions, so a call that passes its own incoming
/// arguments through unchanged (`strlen(arg0)` compiled as just `bl _strlen`) still shows them.
enum Signatures {
    static let known: [String: (count: Int, variadic: Bool)] = {
        var d: [String: (Int, Bool)] = [:]
        let fixed: [Int: [String]] = [
            0: ["abort", "dlerror", "pthread_self", "__stack_chk_fail", "objc_autoreleasePoolPush", "dispatch_get_main_queue", "getpid", "rand", "__error",
                "objc_terminate", "CFRunLoopGetMain", "CFRunLoopGetCurrent", "CFAbsoluteTimeGetCurrent"],
            1: ["strlen", "strdup", "malloc", "free", "puts", "putchar", "exit", "_exit", "atoi", "atol", "atof", "getenv", "close",
                "fclose", "fflush", "unlink", "rmdir", "chdir", "isalpha", "isdigit", "isspace", "isupper", "islower", "toupper",
                "tolower", "sleep", "usleep", "srand", "time", "localtime", "gmtime", "mktime", "pthread_mutex_lock",
                "pthread_mutex_unlock", "pthread_mutex_destroy", "dlclose", "strerror",
                "objc_retain", "objc_release", "objc_autorelease", "objc_retainAutorelease", "objc_retainAutoreleasedReturnValue",
                "objc_autoreleaseReturnValue", "objc_retainAutoreleaseReturnValue", "objc_claimAutoreleasedReturnValue",
                "objc_unsafeClaimAutoreleasedReturnValue", "objc_autoreleasePoolPop", "objc_alloc", "objc_alloc_init",
                "objc_opt_class", "objc_opt_new", "objc_opt_self", "objc_loadWeakRetained", "objc_loadWeak", "objc_destroyWeak",
                "objc_getClass", "objc_retainBlock", "object_getClass", "sel_registerName", "NSStringFromClass",
                "NSStringFromSelector", "NSClassFromString", "NSSelectorFromString", "_Block_copy", "_Block_release",
                "swift_retain", "swift_release", "swift_bridgeObjectRetain", "swift_bridgeObjectRelease", "swift_unknownObjectRetain",
                "swift_unknownObjectRelease", "swift_endAccess", "swift_errorRelease", "swift_errorRetain",
                "swift_isUniquelyReferenced_nonNull_native", "CFRelease", "CFRetain",
                "dispatch_release", "dispatch_retain", "os_release", "os_retain"],
            2: ["strcmp", "swift_dynamicCastClass", "swift_getKeyPath", "strcpy", "strcat", "strchr", "strrchr", "strstr", "strspn", "strcspn", "strpbrk", "calloc", "realloc",
                "fputs", "fopen", "fputc", "putc", "rename", "access", "mkdir", "stat", "lstat", "fstat", "kill", "signal",
                "pthread_mutex_init", "pthread_join", "dlopen", "dlsym", "gettimeofday", "strtod", "setlocale",
                "objc_storeStrong", "objc_storeWeak", "objc_initWeak", "objc_copyWeak", "objc_moveWeak", "objc_opt_isKindOfClass",
                "objc_opt_respondsToSelector", "objc_getAssociatedObject", "class_getInstanceMethod",
                "dispatch_once", "dispatch_async", "dispatch_sync", "dispatch_barrier_async", "dispatch_queue_create",
                "_Block_object_dispose"],
            3: ["strncmp", "strncpy", "strncat", "memcpy", "memmove", "memset", "memcmp", "memchr", "read", "write", "strtol",
                "strtoul", "strtoll", "strtoull", "setenv", "lseek", "fseek", "dispatch_after",
                "dispatch_group_async", "_Block_object_assign", "swift_allocObject", "swift_once", "swift_getWitnessTable",
                "swift_deallocClassInstance"],
            4: ["fwrite", "pthread_create", "fread", "qsort", "objc_getProperty", "objc_setAssociatedObject", "swift_beginAccess"],
            5: ["bsearch"],
            6: ["objc_setProperty"],
        ]
        for (n, names) in fixed { for name in names { d[name] = (n, false) } }
        let variadic: [Int: [String]] = [
            1: ["printf", "NSLog", "scanf", "open"],
            2: ["fprintf", "sprintf", "asprintf", "sscanf", "fscanf", "syslog", "fcntl", "ioctl", "dprintf"],
            3: ["snprintf"],
        ]
        for (n, names) in variadic { for name in names { d[name] = (n, true) } }
        return d
    }()
}
