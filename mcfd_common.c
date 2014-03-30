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

void setup_signal_handlers(void)
{
	sigset_t mask;
	(void)sigemptyset(&mask);
	(void)sigaddset(&mask, SIGTERM);
	(void)sigaddset(&mask, SIGINT);
	(void)sigaddset(&mask, SIGQUIT);
	(void)sigaddset(&mask, SIGCHLD);

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
