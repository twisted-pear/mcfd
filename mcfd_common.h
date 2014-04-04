#ifndef __MCFD_COMMON_H__
#define __MCFD_COMMON_H__

extern const char *progname;
extern void cleanup(void);

void terminate(const int exitCode);

void print_buf(const unsigned char *buf, size_t len);
void print_err(const char *const action, const char *const reason);

void block_signals(void);
void unblock_signals(void);
void setup_signal_handlers(void);

void reverse_bytes(unsigned char *bytes, size_t n);

#endif /* __MCFD_COMMON_H__ */
