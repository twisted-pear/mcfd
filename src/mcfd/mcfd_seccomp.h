#ifndef __MCFD_SECCOMP_H__
#define __MCFD_SECCOMP_H__

int mcfd_seccomp_preconnect(int allow_fork);

int mcfd_seccomp_preauth_server(void);
int mcfd_seccomp_preauth_client(void);
int mcfd_seccomp_preauth_sink(void);
int mcfd_seccomp_preauth_source(void);

int mcfd_seccomp_postauth(void);

#endif /* __MCFD_SECCOMP_H__ */
