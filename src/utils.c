
#include "common.h"
#include "utils.h"

void skip_spaces(const char * * const str)
{
    const char *s = *str;
    while (*s != 0 && isspace((unsigned char ) *s)) {
        s++;
    }
    *str = s;
}

int safe_write(const int fd, const void * const buf_, size_t count,
               const int timeout)
{
    const char *buf = (const char *) buf_;
    ssize_t written;
    struct pollfd pfd;
    
    pfd.fd = fd;
    pfd.events = POLLOUT;
    
    while (count > (size_t) 0) {
        for (;;) {
            if ((written = write(fd, buf, count)) <= (ssize_t) 0) {
                if (errno == EAGAIN) {
                    if (poll(&pfd, (nfds_t) 1, timeout) == 0) {
                        errno = ETIMEDOUT;
                        return -1;
                    }
                } else if (errno != EINTR) {
                    return -1;
                }
                continue;
            }
            break;
        }
        buf += written;
        count -= written;
    }
    return 0;
}

ssize_t safe_read(const int fd, void * const buf_, size_t maxlen)
{
    unsigned char *buf = (unsigned char *) buf_;
    ssize_t readnb;
    
    do {
        while ((readnb = read(fd, buf, maxlen)) < (ssize_t) 0 &&
               errno == EINTR);
        if (readnb < (ssize_t) 0 || readnb > (ssize_t) maxlen) {
            return readnb;
        }
        if (readnb == (ssize_t) 0) {
ret:
            return (ssize_t) (buf - (unsigned char *) buf_);
        }
        maxlen -= readnb;
        buf += readnb;
    } while (maxlen > (ssize_t) 0);
    goto ret;
}


int fcntl_or_flags(const int socket, const int or_flags)
{
    int flags;
    
    if ((flags = fcntl(socket, F_GETFL, 0)) == -1) {
        flags = 0;
    }
    return fcntl(socket, F_SETFL, flags | or_flags);
}

int fcntl_nand_flags(const int socket, const int nand_flags)
{
    int flags;
    
    if ((flags = fcntl(socket, F_GETFL, 0)) == -1) {
        flags = 0;
    }
    return fcntl(socket, F_SETFL, flags & ~nand_flags);
}

static unsigned int open_max(void)
{
    long z;
    
    if ((z = (long) sysconf(_SC_OPEN_MAX)) < 0L) {
        logfile_error(NULL, "_SC_OPEN_MAX");
        return 2U;
    }
    return (unsigned int) z;
}

static int closedesc_all(const int closestdin)
{
    int fodder;
    
    if (closestdin != 0) {
        (void) close(0);
        if ((fodder = open("/dev/null", O_RDONLY)) == -1) {
            return -1;
        }
        (void) dup2(fodder, 0);
        if (fodder > 0) {
            (void) close(fodder);
        }
    }
    if ((fodder = open("/dev/null", O_WRONLY)) == -1) {
        return -1;
    }
    (void) dup2(fodder, 1);
    (void) dup2(1, 2);
    if (fodder > 2) {
        (void) close(fodder);
    }
    
    return 0;
}

int do_daemonize(void)
{
    pid_t child;
    unsigned int i;
    
    if ((child = fork()) == (pid_t) -1) {
        logfile_error(NULL, "Unable to fork() in order to daemonize");
        return -1;
    } else if (child != (pid_t) 0) {
        _exit(0);
    }
    if (setsid() == (pid_t) -1) {
        logfile_error(NULL, "Unable to setsid()");
    }
    i = open_max();
    do {
        if (isatty((int) i)) {
            (void) close((int) i);
        }
        i--;
    } while (i > 2U);
    if (closedesc_all(1) != 0) {
        logfile_error(NULL, "/dev/null duplication");
        return -1;
    }        
    return 0;
}
