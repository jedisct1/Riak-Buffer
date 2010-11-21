
#ifndef __UTILS_H__
#define __UTILS_H__ 1

void skip_spaces(const char * * const str);

int safe_write(const int fd, const void * const buf_, size_t count,
               const int timeout);
ssize_t safe_read(const int fd, void * const buf_, size_t maxlen);

int fcntl_or_flags(const int socket, const int or_flags);
int fcntl_nand_flags(const int socket, const int nand_flags);

int do_daemonize(void);

#endif
