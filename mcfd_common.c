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

void print_err(const char *const action, const char *const reason)
{
	(void)fprintf(stderr, "%s [ERROR] %s: %s\n", progname, action, reason);
}

static void handle_signal(int signal)
{
	terminate(EXIT_SUCCESS);
}

static void handle_child(int signal)
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

	assert(sigprocmask(SIG_BLOCK, &mask, NULL) == 0);
}

void unblock_signals(void)
{
	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGQUIT);

	assert(sigprocmask(SIG_UNBLOCK, &mask, NULL) == 0);
}

void setup_signal_handlers(void)
{
	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGQUIT);
	sigaddset(&mask, SIGCHLD);

	struct sigaction act;
	act.sa_handler = handle_signal;
	act.sa_mask = mask;
	act.sa_flags = 0;
	act.sa_restorer = NULL;

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

	act.sa_handler = handle_child;
	act.sa_mask = mask;
	act.sa_flags = 0;
	act.sa_restorer = NULL;

	if (sigaction(SIGCHLD, &act, NULL) < 0) {
		print_err("set SIGCHLD signal handler", strerror(errno));
		terminate(EXIT_FAILURE);
	}
}

/* This function shamelessly stolen from https://stackoverflow.com/questions/2602823/. */
unsigned char reverse_bits(unsigned char b)
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