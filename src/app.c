
#define DEFINE_GLOBALS 1

#include "common.h"
#include "app_config.h"

/* Work in progress... Crappy useless code for now... you've been warned... */

static struct event_base *ev_base;
static struct evdns_base *evdns_base;
static struct bufferevent *queue[2];
static struct bufferevent *queue_sender, *queue_receiver;

static void make_http_request_for_message(Message * const message);

static void retain_message(Message * const message)
{    
    assert(message->ref_cnt < UINT_MAX);
    message->ref_cnt++;
}

static void free_message(Message * const message)
{
    assert(message->ref_cnt == 0U);
    free(message->bucket);
    message->bucket = NULL;
    message->bucket_len = (size_t) 0U;
    free(message->data);
    message->data = NULL;
    message->data_len = (size_t) 0U;
    free(message);
}

static void release_message(Message * const message)
{
    assert(message->ref_cnt > 0U);
    message->ref_cnt--;
    if (message->ref_cnt > 0) {
        return;
    }
    free_message(message);
}

static void http_reschedule_cb(evutil_socket_t fd, short event,
                               void * const message_)
{
    Message * const message = message_;
    assert(event_initialized(&message->ev_timer));
    memset(&message->ev_timer, 0, sizeof message->ev_timer);
    make_http_request_for_message(message);
}

static void http_reschedule(struct evhttp_request *ev_req,
                            Message * const message)
{
    struct event *ev;
    struct timeval tv;    
    assert(!event_initialized(&message->ev_timer));
    evtimer_assign(&message->ev_timer, ev_base, http_reschedule_cb, message);
    tv = (struct timeval) {
        .tv_sec = app_context.retry_interval,
        .tv_usec = 0
    };
    evtimer_add(&message->ev_timer, &tv);
}

static void http_request_done(struct evhttp_request *ev_req,
                              void * const message_)
{
    Message * const message = message_;

    assert(message->ev_conn != NULL);
    evhttp_connection_free(message->ev_conn);
    message->ev_conn = NULL;    
    if (ev_req == NULL) {
        http_reschedule(ev_req, message);
        return;
    }
    const int code = evhttp_request_get_response_code(ev_req);
    if (code == 0) {
        http_reschedule(ev_req, message);
        return;
    }
    bufferevent_enable(queue_receiver, EV_READ);
    release_message(message);
}

static void make_http_request_for_message(Message * const message)
{
    struct evhttp_connection *ev_conn;
    struct evhttp_request *ev_req;    
    const struct evhttp_uri ** const ev_uri_pnt =
        pnt_stack_cyterator_next(&app_context.riak_uris_iterator);    
    const struct evhttp_uri *ev_uri = *ev_uri_pnt;
    const char * host = evhttp_uri_get_host(ev_uri);
    const int port = evhttp_uri_get_port(ev_uri);
    
    ev_conn = evhttp_connection_base_new(ev_base, evdns_base, host, port);
    ev_req = evhttp_request_new(http_request_done, message);
    evhttp_add_header(evhttp_request_get_output_headers(ev_req),
                      "Host", host);
    evhttp_add_header(evhttp_request_get_output_headers(ev_req),
                      "Content-Type", "application/json");
    evbuffer_add(evhttp_request_get_output_buffer(ev_req),
                 message->data, message->data_len);
    message->ev_conn = ev_conn;    
    const char * const path = evhttp_uri_get_path(ev_uri);
    const size_t path_len = strlen(path);
    const size_t sizeof_uri = path_len + message->bucket_len + (size_t) 1U;
    char *uri = ALLOCA(sizeof_uri);
    memcpy(uri, path, path_len);
    memcpy(uri + path_len, message->bucket, message->bucket_len);
    *(uri + sizeof_uri - (size_t) 1U) = 0;
    evhttp_make_request(ev_conn, ev_req, EVHTTP_REQ_POST, uri);
    ALLOCA_FREE(uri);
}

static void message_received_cb(struct bufferevent *bev, void * context_)
{
    Message *message;
    struct evbuffer *input = bufferevent_get_input(bev);
    size_t len = evbuffer_get_length(input);
    assert(len >= sizeof message);   
    bufferevent_read(bev, &message, sizeof message);
    assert(bev == queue_receiver);
    bufferevent_disable(queue_receiver, EV_READ);
    make_http_request_for_message(message);
}

static void push_read_bucket_len_cb(struct bufferevent *bev, void *ctx);

static void error_event_cb(struct bufferevent *bev, short what, void * client_)
{    
    Client * client = client_;
    struct evbuffer *input = bufferevent_get_input(bev);
    const size_t len = evbuffer_get_length(input);
    
    release_message(client->message);
    free(client);
    bufferevent_free(bev);
}

static void push_read_data_cb(struct bufferevent *bev, void * client_)
{
    Client * const client = client_;
    Message * const message = client->message;
    struct evbuffer *input = bufferevent_get_input(bev);    
    size_t len = evbuffer_get_length(input);
    size_t data_len = message->data_len;
    
    assert(len >= message->data_len);
    message->data = malloc(data_len);
    bufferevent_read(bev, message->data, data_len);
    
    struct evbuffer * const output = bufferevent_get_output(bev);
    
    evbuffer_add(output, "OK\n", sizeof "OK\n" - 1U);
    bufferevent_setwatermark(bev, EV_READ, 4, 4);
    bufferevent_setcb(bev, push_read_bucket_len_cb, NULL,
                      error_event_cb, client);
    bufferevent_write(queue_sender, &message, sizeof message);
    retain_message(message);
}

static void push_read_data_len_cb(struct bufferevent *bev, void * client_)
{
    Client * const client = client_;
    Message * const message = client->message;
    struct evbuffer *input = bufferevent_get_input(bev);
    size_t len = evbuffer_get_length(input);    
    uint32_t net_data_len;
    
    bufferevent_read(bev, &net_data_len, sizeof net_data_len);
    size_t data_len = ntohl(net_data_len);
    message->data_len = data_len;
    bufferevent_setwatermark(bev, EV_READ, data_len, data_len);
    bufferevent_setcb(bev, push_read_data_cb, NULL, error_event_cb, client);
}

static void push_read_bucket_cb(struct bufferevent *bev, void * client_)
{
    Client * const client = client_;
    Message * const message = client->message;
    struct evbuffer *input = bufferevent_get_input(bev);    
    size_t len = evbuffer_get_length(input);
    size_t bucket_len = message->bucket_len;
    
    assert(len >= message->bucket_len);
    message->bucket = malloc(bucket_len);
    bufferevent_read(bev, message->bucket, bucket_len);
    struct evbuffer *output = bufferevent_get_output(bev);
    bufferevent_setwatermark(bev, EV_READ, 4, 4);
    bufferevent_setcb(bev, push_read_data_len_cb, NULL,
                      error_event_cb, client);
}

static void push_read_bucket_len_cb(struct bufferevent *bev, void * client_)
{
    Client * const client = client_;
    Message * const message = client->message;
    struct evbuffer *input = bufferevent_get_input(bev);
    size_t len = evbuffer_get_length(input);    
    uint32_t net_bucket_len;
    bufferevent_read(bev, &net_bucket_len, sizeof net_bucket_len);
    size_t bucket_len = ntohl(net_bucket_len);
    message->bucket_len = bucket_len;
    bufferevent_setwatermark(bev, EV_READ, bucket_len, bucket_len);
    bufferevent_setcb(bev, push_read_bucket_cb, NULL, error_event_cb, client);
}

static void accept_conn_cb(struct evconnlistener * listener,
                           evutil_socket_t fd, struct sockaddr * address,
                           int socklen, void * context_)
{
    struct event_base *base = evconnlistener_get_base(listener);
    struct bufferevent *bev = bufferevent_socket_new
        (ev_base, fd, BEV_OPT_CLOSE_ON_FREE);
    Client * const client = malloc(sizeof *client);    
    Message * const message = malloc(sizeof *message);
    message->ref_cnt = 1U;
    message->bucket_len = (size_t) 0U;
    message->bucket = NULL;
    message->data_len = (size_t) 0U;    
    message->data = NULL;
    memset(&message->ev_timer, 0, sizeof message->ev_timer);
    message->ev_conn = NULL;
    client->message = message;
    bufferevent_setcb(bev, push_read_bucket_len_cb, NULL,
                      error_event_cb, client);
    bufferevent_setwatermark(bev, EV_READ, 4, 4);
    bufferevent_enable(bev, EV_READ);
}

static int open_log_file(void)
{
    int flags = O_RDWR | O_CREAT | O_APPEND;
#ifdef O_EXLOCK
    flags |= O_EXLOCK;
#endif
#ifdef O_NOATIME
    flags |= O_NOATIME;
#endif
#ifdef O_LARGEFILE
    flags |= O_LARGEFILE;
#endif
    assert(app_context.log_fd == -1);
    if (app_context.log_file_name == NULL) {
        return 0;
    }
    app_context.log_fd = open(app_context.log_file_name,
                              flags, (mode_t) 0600);
    if (app_context.log_fd == -1) {
        logfile(NULL, LOG_ERR, "Can't open [%s]: [%s]",
                app_context.log_file_name,
                strerror(errno));
        return -1;
    }
    return 0;
}

static int close_log_file(void)
{
    if (app_context.log_fd != -1) {
        fsync(app_context.log_fd);
        close(app_context.log_fd);
        app_context.log_fd = -1;
    }
    return 0;
}

static void usage(void)
{
    puts("\nUsage: riakbuffer <configuration file>\n");
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        usage();
        return 1;
    }
    check_sys_config();
    
    if (parse_config(argv[1]) != 0) {
        return 2;
    }
    if (app_context.daemonize != 0 && do_daemonize() != 0) {
        return 3;
    }

    open_log_file();

    ev_base = event_base_new();
    evdns_base = evdns_base_new(ev_base, 1);
    bufferevent_pair_new(ev_base,
                         BEV_OPT_CLOSE_ON_FREE  |
                         BEV_OPT_DEFER_CALLBACKS |
                         BEV_OPT_UNLOCK_CALLBACKS, queue);
    queue_sender = queue[0];
    queue_receiver = queue[1];
    bufferevent_setwatermark(queue_receiver, EV_READ,
                             sizeof(Message *), sizeof(Message *));
    bufferevent_setcb(queue_receiver, message_received_cb, NULL, NULL, NULL);
    bufferevent_enable(queue_receiver, EV_READ);

    struct evutil_addrinfo * ai;
    struct evutil_addrinfo hints;
    
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = EVUTIL_AI_PASSIVE | EVUTIL_AI_ADDRCONFIG;
    
    const int gai_err = evutil_getaddrinfo(app_context.server_ip,
                                           app_context.server_port,
                                           &hints, &ai);
    if (gai_err != 0) {
        logfile(&app_context, LOG_ERR,
                "Unable to start the server: [%s]",
                gai_strerror(gai_err));
        return -1;
    }
    struct evconnlistener *listener;    
    listener = evconnlistener_new_bind
        (ev_base, accept_conn_cb, NULL,
            LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_EXEC,
            -1, ai->ai_addr, ai->ai_addrlen);
    evutil_freeaddrinfo(ai);
    event_base_dispatch(ev_base);
    evconnlistener_free(listener);
    event_base_free(ev_base);
    close_log_file();

    free_config();
    
    return 0;
}
