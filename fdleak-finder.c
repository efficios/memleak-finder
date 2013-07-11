/*
 * fd-finder.c
 *
 * File descriptor leak finder
 *
 * Copyright (c) 2013 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <stdarg.h>
#include <execinfo.h>
#include <sys/epoll.h>
#include <sys/prctl.h>	/* prctl */
#include <errno.h>
#include "hlist.h"

#include "jhash.h"

#define BACKTRACE_LEN			16
#define MAX_NUM_FD			65536
#define DEFAULT_PRINT_BACKTRACE_LEN	3
#define PROCNAME_LEN			17

#ifdef __linux__
#include <syscall.h>
#endif

#if defined(_syscall0)
_syscall0(pid_t, gettid)
#elif defined(__NR_gettid)
#include <unistd.h>
static inline pid_t gettid(void)
{
	return syscall(__NR_gettid);
}
#else
#include <sys/types.h>
#include <unistd.h>

/* Fall-back on getpid for tid if not available. */
static inline pid_t gettid(void)
{
	return getpid();
}
#endif

#define fdl_printf(fmt, args...) \
	fprintf(stderr, "[fdleak %s %ld/%ld] "  fmt, \
		proc_name, (long) getpid(), (long) gettid(), ## args)

static volatile int print_to_console,
		print_backtrace_len = DEFAULT_PRINT_BACKTRACE_LEN;
static char proc_name[PROCNAME_LEN];

static pthread_mutex_t fd_mutex = PTHREAD_MUTEX_INITIALIZER;

static int (*openp)(const char *pathname, int flags, mode_t mode);
static int (*creatp)(const char *pathname, mode_t mode);
static int (*dupp)(int oldfd);
static int (*dup2p)(int oldfd, int newfd);
static int (*dup3p)(int oldfd, int newfd, int flags);
static int (*socketp)(int domain, int type, int protocol);
static int (*acceptp)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
static int (*accept4p)(int sockfd, struct sockaddr *addr, socklen_t *addrlen,
		int flags);
static int (*shm_openp)(const char *name, int oflag, mode_t mode);
static int (*pipep)(int pipefd[2]);
static int (*pipe2p)(int pipefd[2], int flags);
static int (*epoll_createp)(int size);
static int (*epoll_create1p)(int flags);
static int (*closep)(int fd);
/* TODO: recvmsg, recvmmsg unix socket */

static volatile int initialized;
static __thread int thread_in_hook;

#define FD_HASH_BITS	20	/* 1 M entries, hardcoded for now */
#define FD_TABLE_SIZE	(1 << FD_HASH_BITS)
static struct cds_hlist_head fd_table[FD_TABLE_SIZE];

struct backtrace {
	void *ptrs[BACKTRACE_LEN];
	char **symbols;
};

struct fd_entry {
	struct cds_hlist_node hlist;
	int fd;
	const void *caller;
	char *caller_symbol;
	struct backtrace bt;
};

static struct fd_entry *
get_fd(int fd)
{
	struct cds_hlist_head *head;
	struct cds_hlist_node *node;
	struct fd_entry *e;
	uint32_t hash;

	hash = jhash(&fd, sizeof(fd), 0);
	head = &fd_table[hash & (FD_TABLE_SIZE - 1)];
	cds_hlist_for_each_entry(e, node, head, hlist) {
		if (fd == e->fd)
			return e;
	}
	return NULL;
}

/*
 * Allocates a string, or NULL.
 */
static
char *get_symbol(const void *caller)
{
	Dl_info info;
	char *caller_symbol;

	if (caller && dladdr(caller, &info) && info.dli_sname) {
		caller_symbol = strdup(info.dli_sname);
	} else {
		caller_symbol = NULL;
	}
	return caller_symbol;
}

static inline __attribute__((always_inline))
void save_backtrace(struct backtrace *bt)
{
	memset(bt, 0, sizeof(*bt));
	(void) backtrace(bt->ptrs, BACKTRACE_LEN);
	bt->symbols = backtrace_symbols(bt->ptrs, BACKTRACE_LEN);
}

static
void free_backtrace(struct backtrace *bt)
{
	free(bt->symbols);
}

static
void print_bt(struct backtrace *bt)
{
	int j;
	unsigned int empty = 1;

	for (j = 0; j < BACKTRACE_LEN; j++) {
		if (bt->ptrs[j]) {
			empty = 0;
			break;
		}
	}
	if (empty)
		return;

	fdl_printf("[backtrace]\n");
	for (j = 0; j < BACKTRACE_LEN && j < print_backtrace_len; j++) {
		if (!bt->ptrs[j])
			continue;
		if (bt->symbols)
			fdl_printf(" %p <%s>\n", bt->ptrs[j], bt->symbols[j]);
		else
			fdl_printf(" %p\n", bt->ptrs[j]);
	}
}

static void
add_fd(int fd, const void *caller, struct backtrace *bt)
{
	struct cds_hlist_head *head;
	struct cds_hlist_node *node;
	struct fd_entry *e;
	uint32_t hash;
	char *caller_symbol;

	if (fd < 0)
		return;
	hash = jhash(&fd, sizeof(fd), 0);
	head = &fd_table[hash & (FD_TABLE_SIZE - 1)];
	caller_symbol = get_symbol(caller);
	cds_hlist_for_each_entry(e, node, head, hlist) {
		if (fd == e->fd) {
			fdl_printf("[warning] add_fd fd %d is already there, caller %p <%s>\n",
				fd, caller, caller_symbol);
			print_bt(bt);
			//assert(0);	/* already there */
		}
	}
	e = calloc(1, sizeof(*e));
	e->fd = fd;
	e->caller = caller;
	e->caller_symbol = caller_symbol;
	if (bt)
		memcpy(&e->bt, bt, sizeof(*bt));
	cds_hlist_add_head(&e->hlist, head);
}

static void
del_fd(int fd, const void *caller, struct backtrace *bt, int needclose)
{
	struct fd_entry *e;

	if (fd < 0)
		return;
	e = get_fd(fd);
	if (!e) {
		if (needclose) {
			char *caller_symbol;

			caller_symbol = get_symbol(caller);
			fdl_printf("[warning] trying to free unallocated fd %d caller %p <%s>\n",
				fd, caller, caller_symbol);
			print_bt(bt);
			free(caller_symbol);
		}
		return;
	}
	cds_hlist_del(&e->hlist);
	free(e->caller_symbol);
	free_backtrace(&e->bt);
	free(e);
}

static void
do_init(void)
{
	char *env;

	if (initialized)
		return;

	(void) prctl(PR_GET_NAME, (unsigned long) proc_name, 0, 0, 0);
	openp = (int (*) (const char *, int, mode_t)) dlsym(RTLD_NEXT, "open");
	creatp = (int (*) (const char *, mode_t)) dlsym(RTLD_NEXT, "creat");
	dupp = (int (*) (int)) dlsym(RTLD_NEXT, "dup");
	dup2p = (int (*) (int, int)) dlsym(RTLD_NEXT, "dup2");
	dup3p = (int (*) (int, int, int)) dlsym(RTLD_NEXT, "dup3");
	socketp = (int (*) (int, int, int)) dlsym(RTLD_NEXT, "socket");
	acceptp = (int (*) (int, struct sockaddr *, socklen_t *)) dlsym(RTLD_NEXT, "accept");
	accept4p = (int (*) (int, struct sockaddr *, socklen_t *, int)) dlsym(RTLD_NEXT, "accept4");
	shm_openp = (int (*) (const char *, int, mode_t)) dlsym(RTLD_NEXT, "shm_open");
	pipep = (int (*) (int [2])) dlsym(RTLD_NEXT, "pipe");
	pipe2p = (int (*) (int [2], int)) dlsym(RTLD_NEXT, "pipe2");
	epoll_createp = (int (*) (int)) dlsym(RTLD_NEXT, "epoll_create");
	epoll_create1p = (int (*) (int)) dlsym(RTLD_NEXT, "epoll_create1");
	closep = (int (*) (int)) dlsym(RTLD_NEXT, "close");

	env = getenv("FDLEAK_FINDER_PRINT");
	if (env && strcmp(env, "1") == 0)
		print_to_console = 1;

	env = getenv("FDLEAK_BACKTRACE_LEN");
	if (env)
		print_backtrace_len = atoi(env);

	initialized = 1;
}

int open(const char *pathname, int flags, ...)
{
	int result;
	const void *caller = __builtin_return_address(0);
	va_list ap;
	mode_t mode;
	struct backtrace bt;

	va_start(ap, flags);

	mode = va_arg(ap, mode_t);

	do_init();

	if (thread_in_hook) {
		result = openp(pathname, flags, mode);
		goto end;
	}

	thread_in_hook = 1;

	pthread_mutex_lock(&fd_mutex);

	/* Call resursively */
	result = openp(pathname, flags, mode);
	if (result >= 0) {
		save_backtrace(&bt);
		add_fd(result, caller, &bt);
	}

	/* printf might call malloc, so protect it too. */
	if (print_to_console)
		fdl_printf("open(%p,%d,%d) returns %d\n",
			pathname, flags, mode, result);

	pthread_mutex_unlock(&fd_mutex);

	thread_in_hook = 0;
end:
	va_end(ap);
	return result;
}

int creat(const char *pathname, mode_t mode)
{
	int result;
	const void *caller = __builtin_return_address(0);
	struct backtrace bt;

	do_init();

	if (thread_in_hook) {
		return creatp(pathname, mode);
	}

	thread_in_hook = 1;

	pthread_mutex_lock(&fd_mutex);

	/* Call resursively */
	result = creatp(pathname, mode);
	if (result >= 0) {
		save_backtrace(&bt);
		add_fd(result, caller, &bt);
	}

	/* printf might call malloc, so protect it too. */
	if (print_to_console)
		fdl_printf("creat(%p,%d) returns %d\n",
			pathname, mode, result);

	pthread_mutex_unlock(&fd_mutex);

	thread_in_hook = 0;

	return result;
}

int dup(int oldfd)
{
	int result;
	const void *caller = __builtin_return_address(0);
	struct backtrace bt;

	do_init();

	if (thread_in_hook) {
		return dupp(oldfd);
	}

	thread_in_hook = 1;

	pthread_mutex_lock(&fd_mutex);

	/* Call resursively */
	result = dupp(oldfd);
	if (result >= 0) {
		save_backtrace(&bt);
		add_fd(result, caller, &bt);
	}

	/* printf might call malloc, so protect it too. */
	if (print_to_console)
		fdl_printf("dup(%d) returns %d\n",
			oldfd, result);

	pthread_mutex_unlock(&fd_mutex);

	thread_in_hook = 0;

	return result;
}

int dup2(int oldfd, int newfd)
{
	int result;
	const void *caller = __builtin_return_address(0);
	struct backtrace bt;

	do_init();

	if (thread_in_hook) {
		return dup2p(oldfd, newfd);
	}

	thread_in_hook = 1;

	pthread_mutex_lock(&fd_mutex);

	/* Call resursively */
	result = dup2p(oldfd, newfd);
	if (result >= 0 && oldfd != newfd) {
		save_backtrace(&bt);
		/* Closes newfd if it was there. */
		del_fd(newfd, caller, &bt, 0);
		add_fd(result, caller, &bt);
	}

	/* printf might call malloc, so protect it too. */
	if (print_to_console)
		fdl_printf("dup2(%d,%d) returns %d\n",
			oldfd, newfd, result);

	pthread_mutex_unlock(&fd_mutex);

	thread_in_hook = 0;

	return result;
}

int dup3(int oldfd, int newfd, int flags)
{
	int result;
	const void *caller = __builtin_return_address(0);
	struct backtrace bt;

	do_init();

	if (thread_in_hook) {
		return dup3p(oldfd, newfd, flags);
	}

	thread_in_hook = 1;

	pthread_mutex_lock(&fd_mutex);

	/* Call resursively */
	result = dup3p(oldfd, newfd, flags);
	if (result >= 0 && oldfd != newfd) {
		/* Closes newfd if it was there. */
		save_backtrace(&bt);
		del_fd(newfd, caller, &bt, 0);
		add_fd(result, caller, &bt);
	}

	/* printf might call malloc, so protect it too. */
	if (print_to_console)
		fdl_printf("dup3(%d,%d,%d) returns %d\n",
			oldfd, newfd, flags, result);

	pthread_mutex_unlock(&fd_mutex);

	thread_in_hook = 0;

	return result;
}

int socket(int domain, int type, int protocol)
{
	int result;
	const void *caller = __builtin_return_address(0);
	struct backtrace bt;

	do_init();

	if (thread_in_hook) {
		return socketp(domain, type, protocol);
	}

	thread_in_hook = 1;

	pthread_mutex_lock(&fd_mutex);

	/* Call resursively */
	result = socketp(domain, type, protocol);
	if (result >= 0) {
		save_backtrace(&bt);
		add_fd(result, caller, &bt);
	}

	/* printf might call malloc, so protect it too. */
	if (print_to_console)
		fdl_printf("socket(%d,%d,%d) returns %d\n",
			domain, type, protocol, result);

	pthread_mutex_unlock(&fd_mutex);

	thread_in_hook = 0;

	return result;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	int result;
	const void *caller = __builtin_return_address(0);
	struct backtrace bt;

	do_init();

	if (thread_in_hook) {
		return acceptp(sockfd, addr, addrlen);
	}

	thread_in_hook = 1;

	pthread_mutex_lock(&fd_mutex);

	/* Call resursively */
	result = acceptp(sockfd, addr, addrlen);
	if (result >= 0) {
		save_backtrace(&bt);
		add_fd(result, caller, &bt);
	}

	/* printf might call malloc, so protect it too. */
	if (print_to_console)
		fdl_printf("accept(%d,%p,%p) returns %d\n",
			sockfd, addr, addrlen, result);

	pthread_mutex_unlock(&fd_mutex);

	thread_in_hook = 0;

	return result;
}

int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen,
		int flags)
{
	int result;
	const void *caller = __builtin_return_address(0);
	struct backtrace bt;

	do_init();

	if (thread_in_hook) {
		return accept4p(sockfd, addr, addrlen, flags);
	}

	thread_in_hook = 1;

	pthread_mutex_lock(&fd_mutex);

	/* Call resursively */
	result = accept4p(sockfd, addr, addrlen, flags);
	if (result >= 0) {
		save_backtrace(&bt);
		add_fd(result, caller, &bt);
	}

	/* printf might call malloc, so protect it too. */
	if (print_to_console)
		fdl_printf("accept4(%d,%p,%p,%d) returns %d\n",
			sockfd, addr, addrlen, flags, result);

	pthread_mutex_unlock(&fd_mutex);

	thread_in_hook = 0;

	return result;
}

int shm_open(const char *name, int oflag, mode_t mode)
{
	int result;
	const void *caller = __builtin_return_address(0);
	struct backtrace bt;

	do_init();

	if (thread_in_hook) {
		return shm_openp(name, oflag, mode);
	}

	thread_in_hook = 1;

	pthread_mutex_lock(&fd_mutex);

	/* Call resursively */
	result = shm_openp(name, oflag, mode);
	if (result >= 0) {
		save_backtrace(&bt);
		add_fd(result, caller, &bt);
	}

	/* printf might call malloc, so protect it too. */
	if (print_to_console)
		fdl_printf("shm_open(%s,%d,%d) returns %d\n",
			name, oflag, mode, result);

	pthread_mutex_unlock(&fd_mutex);

	thread_in_hook = 0;

	return result;
}

int pipe(int pipefd[2])
{
	int result;
	const void *caller = __builtin_return_address(0);
	struct backtrace bt[2];

	do_init();

	if (thread_in_hook) {
		return pipep(pipefd);
	}

	thread_in_hook = 1;

	pthread_mutex_lock(&fd_mutex);

	/* Call resursively */
	result = pipep(pipefd);
	if (!result) {
		save_backtrace(&bt[0]);
		save_backtrace(&bt[1]);
		add_fd(pipefd[0], caller, &bt[0]);
		add_fd(pipefd[1], caller, &bt[1]);
	}

	/* printf might call malloc, so protect it too. */
	if (print_to_console)
		fdl_printf("pipe([%d,%d]) returns %d\n",
			pipefd[0], pipefd[1], result);

	pthread_mutex_unlock(&fd_mutex);

	thread_in_hook = 0;

	return result;
}

int pipe2(int pipefd[2], int flags)
{
	int result;
	const void *caller = __builtin_return_address(0);
	struct backtrace bt[2];

	do_init();

	if (thread_in_hook) {
		return pipe2p(pipefd, flags);
	}

	thread_in_hook = 1;

	pthread_mutex_lock(&fd_mutex);

	/* Call resursively */
	result = pipe2p(pipefd, flags);
	if (!result) {
		save_backtrace(&bt[0]);
		save_backtrace(&bt[1]);
		add_fd(pipefd[0], caller, &bt[0]);
		add_fd(pipefd[1], caller, &bt[1]);
	}

	/* printf might call malloc, so protect it too. */
	if (print_to_console)
		fdl_printf("pipe2([%d,%d], %d) returns %d\n",
			pipefd[0], pipefd[1], flags, result);

	pthread_mutex_unlock(&fd_mutex);

	thread_in_hook = 0;

	return result;
}

int epoll_create(int size)
{
	int result;
	const void *caller = __builtin_return_address(0);
	struct backtrace bt;

	do_init();

	if (thread_in_hook) {
		return epoll_createp(size);
	}

	thread_in_hook = 1;

	pthread_mutex_lock(&fd_mutex);

	/* Call resursively */
	result = epoll_createp(size);
	if (result >= 0) {
		save_backtrace(&bt);
		add_fd(result, caller, &bt);
	}
	/* printf might call malloc, so protect it too. */
	if (print_to_console)
		fdl_printf("epoll_create(%d) returns %d\n",
			size, result);

	pthread_mutex_unlock(&fd_mutex);

	thread_in_hook = 0;

	return result;
}

int epoll_create1(int flags)
{
	int result;
	const void *caller = __builtin_return_address(0);
	struct backtrace bt;

	do_init();

	if (thread_in_hook) {
		return epoll_create1p(flags);
	}

	thread_in_hook = 1;

	pthread_mutex_lock(&fd_mutex);

	/* Call resursively */
	result = epoll_create1p(flags);
	if (result >= 0) {
		save_backtrace(&bt);
		add_fd(result, caller, &bt);
	}
	/* printf might call malloc, so protect it too. */
	if (print_to_console)
		fdl_printf("epoll_create1(%d) returns %d\n",
			flags, result);

	pthread_mutex_unlock(&fd_mutex);

	thread_in_hook = 0;

	return result;
}

void memleak_finder_export_fd(int fd)
{
	const void *caller = __builtin_return_address(0);
	struct backtrace bt;

	do_init();

	thread_in_hook = 1;

	pthread_mutex_lock(&fd_mutex);

	if (fd >= 0) {
		save_backtrace(&bt);
		add_fd(fd, caller, &bt);
	}

	/* printf might call malloc, so protect it too. */
	if (print_to_console)
		fdl_printf("memleak_finder_export_fd(%d)\n",
			fd);

	pthread_mutex_unlock(&fd_mutex);

	thread_in_hook = 0;
}


int close(int fd)
{
	int result;
	const void *caller = __builtin_return_address(0);
	struct backtrace bt;

	do_init();

	if (thread_in_hook) {
		return closep(fd);
	}

	thread_in_hook = 1;

	pthread_mutex_lock(&fd_mutex);

	/* Call resursively */
	result = closep(fd);
	if (!result) {
		save_backtrace(&bt);
		del_fd(fd, caller, &bt, 1);
	}

	/* printf might call malloc, so protect it too. */
	if (print_to_console)
		fdl_printf("close(%d) returns %d\n",
			fd, result);

	pthread_mutex_unlock(&fd_mutex);

	thread_in_hook = 0;

	return result;
}

/*
 * Library constructor initializing fd tracking. This handles file
 * descriptors present at program startup, e.g. FDs left by an exec()
 * because they did not have the FD_CLOEXEC flag set.
 */
static __attribute((constructor))
void init_fd_tracking(void)
{
	unsigned int fd;

	do_init();
	for (fd = 0; fd < MAX_NUM_FD; fd++) {
		int result;

		/*
		 * Effect-less, but checks if FD exists.
		 */
		result = dup2p(fd, fd);
		if (result != fd)
			continue;
		add_fd(result, NULL, NULL);
		if (print_to_console) {
			fdl_printf("FD %d found at initialization\n",
				result);
		}
	}
}

static __attribute__((destructor))
void print_leaks(void)
{
	unsigned long i;

	for (i = 0; i < FD_TABLE_SIZE; i++) {
		struct cds_hlist_head *head;
		struct cds_hlist_node *node;
		struct fd_entry *e;

		head = &fd_table[i];
		cds_hlist_for_each_entry(e, node, head, hlist) {
			fdl_printf("[leak] fd: %d caller: %p <%s>\n",
				e->fd, e->caller, e->caller_symbol);
			print_bt(&e->bt);
		}
	}
}
