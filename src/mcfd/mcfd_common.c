#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

#include <assert.h>

#include "mcfd_common.h"

void terminate(const int exitCode)
{
	/* Block signals to make sure cleanup doesn't run into trouble. */
	block_signals();
	cleanup();
	exit(exitCode);
	assert(0);
}

void print_buf(const unsigned char *buf, size_t len)
{
	size_t i;

	printf("\n");
	for (i = 0; i < len; i++) {
		printf("%02x ", buf[i]);
	}
	printf("\n");
}

static volatile sig_atomic_t verbosity = 0;
void set_verbosity(int v)
{
	verbosity = v;
}

void print_msg(int severity, const char *const fmt, ...)
{
	va_list argp;
	va_start(argp, fmt);
	vprint_msg(severity, fmt, argp);
	va_end(argp);
}

void vprint_msg(int severity, const char *const fmt, va_list argp)
{
	if (severity > verbosity) {
		return;
	}

	(void) vfprintf(stderr, fmt, argp);
}

static volatile sig_atomic_t handling_signal = 0;
static void handle_signal(int signal)
{
	if (handling_signal != 0) {
		raise(signal);

		assert(0);
		abort();
	}
	handling_signal = 1;

	cleanup();

	/* Restore original signal behaviour for correct exit code. */
	sigset_t mask;
	sigemptyset(&mask);
	struct sigaction act;
	act.sa_handler = SIG_DFL;
	act.sa_mask = mask;
	act.sa_flags = 0;
	if (sigaction(signal, &act, NULL) < 0) {
		terminate(EXIT_FAILURE);
	}

	/* Execute the default signal handler.
	 * The signal will be delivered immediately after the handler exits. */
	raise(signal);
}

static void handle_child(int signal __attribute__((unused)))
{
	/* Use this chance to collect dead children. */
	if (waitpid(-1, NULL, WNOHANG) < 0) {
		print_err("waitpid", strerror(errno));
	}
}

void block_signals(void)
{
	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGQUIT);

	if (sigprocmask(SIG_BLOCK, &mask, NULL) != 0) {
		assert(0);
		abort();
	}
}

void unblock_signals(void)
{
	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGQUIT);

	if (sigprocmask(SIG_UNBLOCK, &mask, NULL) != 0) {
		assert(0);
		abort();
	}
}

void setup_signal_handlers(void)
{
	sigset_t mask;
	sigemptyset(&mask);

	struct sigaction act;
	act.sa_handler = handle_signal;
	act.sa_mask = mask;
	act.sa_flags = 0;

	if (sigaction(SIGTERM, &act, NULL) < 0) {
		print_err("set SIGTERM signal handler", strerror(errno));
		terminate(EXIT_FAILURE);
	}

	if (sigaction(SIGINT, &act, NULL) < 0) {
		print_err("set SIGINT signal handler", strerror(errno));
		terminate(EXIT_FAILURE);
	}

	if (sigaction(SIGQUIT, &act, NULL) < 0) {
		print_err("set SIGQUIT signal handler", strerror(errno));
		terminate(EXIT_FAILURE);
	}

	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGQUIT);
	sigaddset(&mask, SIGCHLD);

	act.sa_handler = handle_child;
	act.sa_mask = mask;
	act.sa_flags = 0;

	if (sigaction(SIGCHLD, &act, NULL) < 0) {
		print_err("set SIGCHLD signal handler", strerror(errno));
		terminate(EXIT_FAILURE);
	}
}

/* This function shamelessly stolen from https://stackoverflow.com/questions/2602823/. */
static unsigned char reverse_bits(unsigned char b)
{
	b = (b & 0xF0) >> 4 | (b & 0x0F) << 4;
	b = (b & 0xCC) >> 2 | (b & 0x33) << 2;
	b = (b & 0xAA) >> 1 | (b & 0x55) << 1;
	return b;
}

void reverse_bytes(unsigned char *bytes, size_t n)
{
	size_t i;
	for (i = 0; i < n / 2; i++) {
		/* swap bytes */
		bytes[i] ^= bytes[(n - 1) - i];
		bytes[(n - 1) - i] ^= bytes[i];
		bytes[i] ^= bytes[(n - 1) - i];
	}

	for (i = 0; i < n; i++) {
		bytes[i] = reverse_bits(bytes[i]);
	}
}
