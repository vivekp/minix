#ifdef __minix
#define DEFAULT_CC		"clang"
#else
#define DEFAULT_CC		"cc"
#endif

char *findcc(const char *);
