int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    /* Ignore debug-level libbpf logs */
    if (level > LIBBPF_INFO)
        return 0;
    return vfprintf(stderr, format, args);
}

void bump_memlock_rlimit() {
    struct rlimit rlim_new = {
            .rlim_cur    = RLIM_INFINITY,
            .rlim_max    = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        std::cerr << "Failed to increase RLIMIT_MEMLOCK limit!" << std::endl;
        std::exit(1);
    }
}