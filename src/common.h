
#ifndef __COMMON_H__
#define __COMMON_H__ 1

#include <config.h>

#ifndef __GNUC__
# ifdef __attribute__
#  undef __attribute__
# endif
# define __attribute__(a)
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <inttypes.h>
#include <stddef.h>
#include <ctype.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <poll.h>
#include <syslog.h>
#include <sys/socket.h>
#include <event.h>
#include <event2/listener.h>
#include <event2/http.h>
#include <event2/dns.h>
#include "stack.h"

#ifdef __APPLE_CC__
int fdatasync(int fd);
#endif

#ifdef HAVE_ALLOCA
# ifdef HAVE_ALLOCA_H
#  include <alloca.h>
# endif
# define ALLOCA(X) alloca(X)
# define ALLOCA_FREE(X) do { } while (0)
#else
# define ALLOCA(X) malloc(X)
# define ALLOCA_FREE(X) free(X)
#endif

typedef struct AppContext_ {
    char *server_ip;
    char *server_port;
    _Bool daemonize;
    char *log_file_name;
    int log_fd;
    PntStack riak_uris;
    PntStackIterator riak_uris_iterator;
} AppContext;

#ifdef DEFINE_GLOBALS
extern AppContext app_context;
#else
AppContext app_context;
#endif

typedef struct Message_ {    
    size_t bucket_len;
    char *bucket;
    size_t data_len;
    char *data;
    unsigned int ref_cnt;    
} Message;

typedef struct Client_ {
    Message *message;
} Client;

#include "log.h"
#include "utils.h"

#endif
