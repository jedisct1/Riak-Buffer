
#include "common.h"
#include "app_config.h"
#include "parser.h"

int parse_config(const char * const file)
{
    char *cfg_server_ip = NULL;
    char *cfg_server_port = NULL;
    char *cfg_daemonize_s = NULL;
    char *cfg_log_file_name = NULL;
    char *cfg_riak_uris = NULL;
    char *cfg_retry_interval_s = NULL;
    int ret = 0;
    ConfigKeywords config_keywords[] = {
        { "ServerIP",               &cfg_server_ip },
        { "ServerPort",             &cfg_server_port },
        { "Daemonize",              &cfg_daemonize_s },
        { "LogFileName",            &cfg_log_file_name },
        { "RiakURIs",               &cfg_riak_uris },
        { "RetryInterval",          &cfg_retry_interval_s },
        { NULL,                     NULL }
    };
    app_context.log_fd = -1;
    app_context.server_ip = NULL;
    app_context.server_port = strdup(DEFAULT_SERVER_PORT);
    app_context.daemonize = 0;
    app_context.log_file_name = NULL;
    app_context.retry_interval = DEFAULT_RETRY_INTERVAL;
    init_pnt_stack(&app_context.riak_uris, (size_t) 1U,
                   sizeof (struct evhttp_uri *));
    init_pnt_stack_iterator(&app_context.riak_uris_iterator,
                            &app_context.riak_uris);    
    if (app_context.server_port == NULL) {
        _exit(1);
    }
    if (generic_parser(file, config_keywords) != 0) {
        logfile(NULL, LOG_ERR,
                "Error while reading the [%s] configuration file.", file);
        return -1;
    }
    char *endptr;
    if (cfg_server_ip != NULL) {
        if (*cfg_server_ip == 0) {
            ret = -1;
        } else {
            free(app_context.server_ip);
            app_context.server_ip = cfg_server_ip;
        }
    }
    if (cfg_server_port != NULL) {
        if (*cfg_server_port == 0) {
            ret = -1;
        } else {
            free(app_context.server_port);            
            app_context.server_port = cfg_server_port;
        }
    }
    if (cfg_daemonize_s != NULL) {
        if (*cfg_daemonize_s == 0) {
            ret = -1;
        } else if (strcasecmp(cfg_daemonize_s, "Yes") == 0 ||
                   strcasecmp(cfg_daemonize_s, "True") == 0 ||
                   strcmp(cfg_daemonize_s, "1") == 0) {            
            app_context.daemonize = 1;
        } else if (strcasecmp(cfg_daemonize_s, "No") == 0 ||
                   strcasecmp(cfg_daemonize_s, "False") == 0 ||
                   strcmp(cfg_daemonize_s, "0") == 0) {
            app_context.daemonize = 0;
        } else {
            ret = -1;
        }
    }
    if (cfg_log_file_name != NULL) {
        if (*cfg_log_file_name == 0) {
            ret = -1;
        } else {
            free(app_context.log_file_name);
            app_context.log_file_name = cfg_log_file_name;
        }
    }
    if (cfg_riak_uris != NULL) {
        if (*cfg_riak_uris == 0) {
            ret = -1;
        } else {
            struct evhttp_uri *ev_uri;
            char *cfg_riak_uri = cfg_riak_uris;
            char *pnt;
            
            for (;;) {
                skip_spaces((const char * *) &cfg_riak_uri);
                pnt = strchr(cfg_riak_uri, ' ');
                if (pnt != NULL) {
                    *pnt = 0;
                }                
                ev_uri = evhttp_uri_parse(cfg_riak_uri);
                if (ev_uri == NULL) {
                    ret = -1;
                    break;
                } else {
                    push_pnt_stack(&app_context.riak_uris, &ev_uri);
                }                                
                if (pnt == NULL) {
                    break;
                }                
                *pnt = ' ';
                cfg_riak_uri = pnt + 1;
            }
        }
    }
    if (cfg_retry_interval_s != NULL) {
        app_context.retry_interval =
            (time_t) strtol(cfg_retry_interval_s, &endptr, 10);
        if (endptr == NULL || endptr == cfg_retry_interval_s ||
            app_context.retry_interval <= (time_t) 0) {
            ret = -1;
        }
    }
    free(cfg_riak_uris);
    free(cfg_daemonize_s);
    free(cfg_retry_interval_s);    
    
    return ret;
}

int check_sys_config(void)
{
    int ret = 0;
    
#ifdef __linux__
    FILE *fp;
    char tmp[100];
        
    if ((fp = fopen("/proc/sys/net/ipv4/tcp_tw_reuse", "r")) != NULL) {
        if (fgets(tmp, sizeof tmp, fp) != NULL) {
            if (atoi(tmp) <= 0) {
                logfile_noformat(NULL, LOG_WARNING,
                                 "Please add net.ipv4.tcp_tw_reuse=1 "
                                 "to /etc/sysctl.conf");
            }
        }
        fclose(fp);
    }
#endif
    return ret;
}

void free_config(void)
{
    free(app_context.server_ip);
    app_context.server_ip = NULL;
    free(app_context.server_port);
    app_context.server_port = NULL;
    free(app_context.log_file_name);
    app_context.log_file_name = NULL;
    free_pnt_stack(&app_context.riak_uris);
}
