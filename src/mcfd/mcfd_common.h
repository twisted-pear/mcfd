#ifndef __MCFD_COMMON_H__
#define __MCFD_COMMON_H__

#include <stdarg.h>
#include <stdnoreturn.h>

extern const char *progname;
extern void cleanup(void);

noreturn void terminate(const int exitCode);

void print_buf(const unsigned char *buf, size_t len);

void set_verbosity(int verbosity);

void print_msg(int severity, const char *const fmt, ...);
void vprint_msg(int severity, const char *const fmt, va_list argp);

#define COLOR_RED	"\x1b[31m"
#define COLOR_GREEN	"\x1b[32m"
#define COLOR_YELLOW	"\x1b[33m"
#define COLOR_BLUE	"\x1b[34m"
#define COLOR_RESET	"\x1b[0m"

#define print_err(action, reason) print_msg(0, \
		"%s [" COLOR_RED "ERROR" COLOR_RESET "] %s: %s\n", \
		progname, action, reason)

void block_signals(void);
void unblock_signals(void);
void setup_signal_handlers(void);

void reverse_bytes(unsigned char *bytes, size_t n);

#endif /* __MCFD_COMMON_H__ */
