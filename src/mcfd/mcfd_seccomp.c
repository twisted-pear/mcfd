#include "mcfd_seccomp.h"

#include <fcntl.h>
#include <unistd.h>
#include <seccomp.h>
#include <sys/prctl.h>

static scmp_filter_ctx base_rules(void)
{
	scmp_filter_ctx *ctx = seccomp_init(SCMP_ACT_KILL);
	if (ctx == NULL) {
		return NULL;
	}

	int err = 0;
	pid_t pid = getpid();

	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvfrom), 0);
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recv), 0);
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendto), 0);
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(send), 0);
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(poll), 0);
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
			SCMP_A0(SCMP_CMP_EQ, STDIN_FILENO));
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
			SCMP_A0(SCMP_CMP_EQ, STDERR_FILENO));
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 0);
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0);
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(tgkill), 2,
			SCMP_A0(SCMP_CMP_EQ, pid),
			SCMP_A1(SCMP_CMP_EQ, pid));
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(kill), 1,
			SCMP_A0(SCMP_CMP_EQ, pid));
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(gettid), 0);
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);

	/* These are needed when profiling is used. */
#ifdef __MCFD_PROFILE__
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 0);
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
#endif /* __MCFD_PROFILE__ */

	if (err != 0) {
		seccomp_release(ctx);
		return NULL;
	}

	return ctx;
}

static int apply_rules(scmp_filter_ctx *ctx)
{
	if (ctx == NULL) {
		return 1;
	}

	if (seccomp_load(ctx) != 0) {
		seccomp_release(ctx);
		return 1;
	}

	seccomp_release(ctx);
	return 0;
}

int mcfd_seccomp_preconnect(int allow_fork)
{
	scmp_filter_ctx *ctx = base_rules();
	if (ctx == NULL) {
		return 1;
	}

	int err = 0;

	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 1,
			SCMP_A1(SCMP_CMP_MASKED_EQ, O_RDONLY|O_WRONLY|O_RDWR, O_RDONLY));
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(stat), 0);
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 0);
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(uname), 0);
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 0);
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(connect), 0);
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setsockopt), 0);
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(bind), 0);
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getsockname), 0);
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvmsg), 0);
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(listen), 0);
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(accept), 0);
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prctl), 1,
			SCMP_A0(SCMP_CMP_EQ, PR_SET_NO_NEW_PRIVS));
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prctl), 1,
			SCMP_A0(SCMP_CMP_EQ, PR_SET_SECCOMP));
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(seccomp), 0);
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrandom), 1,
			SCMP_A2(SCMP_CMP_EQ, 0));
	if (allow_fork != 0) {
		err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clone), 0);
		err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(waitpid), 0);
		err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(wait4), 0);
	}

	if (err != 0) {
		seccomp_release(ctx);
		return 1;
	}

	return apply_rules(ctx);
}

int mcfd_seccomp_preauth_server(void)
{
	scmp_filter_ctx *ctx = base_rules();
	if (ctx == NULL) {
		return 1;
	}

	int err = 0;

	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 0);
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(connect), 0);
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prctl), 1,
			SCMP_A0(SCMP_CMP_EQ, PR_SET_NO_NEW_PRIVS));
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prctl), 1,
			SCMP_A0(SCMP_CMP_EQ, PR_SET_SECCOMP));
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(seccomp), 0);
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrandom), 1,
			SCMP_A2(SCMP_CMP_EQ, 0));

	if (err != 0) {
		seccomp_release(ctx);
		return 1;
	}

	return apply_rules(ctx);
}

int mcfd_seccomp_preauth_client(void)
{
	scmp_filter_ctx *ctx = base_rules();
	if (ctx == NULL) {
		return 1;
	}

	int err = 0;

	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prctl), 1,
			SCMP_A0(SCMP_CMP_EQ, PR_SET_NO_NEW_PRIVS));
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prctl), 1,
			SCMP_A0(SCMP_CMP_EQ, PR_SET_SECCOMP));
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(seccomp), 0);
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrandom), 1,
			SCMP_A2(SCMP_CMP_EQ, 0));

	if (err != 0) {
		seccomp_release(ctx);
		return 1;
	}

	return apply_rules(ctx);
}

int mcfd_seccomp_preauth_sink(void)
{
	scmp_filter_ctx *ctx = base_rules();
	if (ctx == NULL) {
		return 1;
	}

	int err = 0;

	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(accept), 0);
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prctl), 1,
			SCMP_A0(SCMP_CMP_EQ, PR_SET_NO_NEW_PRIVS));
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prctl), 1,
			SCMP_A0(SCMP_CMP_EQ, PR_SET_SECCOMP));
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(seccomp), 0);
	err |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrandom), 1,
			SCMP_A2(SCMP_CMP_EQ, 0));

	if (err != 0) {
		seccomp_release(ctx);
		return 1;
	}

	return apply_rules(ctx);
}

int mcfd_seccomp_preauth_source(void)
{
	return mcfd_seccomp_preauth_server();
}

int mcfd_seccomp_postauth(void)
{
	return apply_rules(base_rules());
}
