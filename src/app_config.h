
#ifndef __APP_CONFIG_H__
#define __APP_CONFIG_H__ 1

#ifndef DEFAULT_SERVER_PORT
# define DEFAULT_SERVER_PORT "4207"
#endif
#ifndef DEFAULT_RETRY_INTERVAL
# define DEFAULT_RETRY_INTERVAL (time_t) 2
#endif

int parse_config(const char * const file);
int check_sys_config(void);
void free_config(void);

#endif
