/*
 * lilyhttpd
 * a simple lil' web server
 */

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static const char PKG_NAME[] = "lilyhttpd v0.0.1";

#define MAX_EVENTS 1024

#define READ_BUF_SIZE 4096
#define WRITE_BUF_SIZE 4096

void sigchld_handler(int s)
{
    (void)s;

    // waitpid() might overwrite errno, so we save and restore it:
    int saved_errno = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0);
    errno = saved_errno;
}

struct config {
    char *root_dir;
    char *port;
    int daemonize;
    int keepalive;
};

static struct config g_config = {
    .root_dir = NULL,
    .port = "8080",
    .daemonize = 0,
    .keepalive = 1,
};

struct connection {
    int fd;
    enum {
        CONN_READING,
        CONN_WRITING,
        CONN_CLOSING
    } state;

    char *req;
    size_t req_len;

    char *method;
    char *url;
    char *host;
    size_t content_length;
    char *user_agent;
    char *content_type;
    char *authorization;

    char *header;
    size_t header_len;

    char *resp;
    size_t resp_len;
};

static struct connection *new_connection()
{
    struct connection *conn = malloc(sizeof(struct connection));

    conn->fd = -1;
    conn->req = NULL;
    conn->req_len = 0;
    conn->method = NULL;
    conn->url = NULL;
    conn->host = NULL;
    conn->content_length = 0;
    conn->user_agent = NULL;
    conn->content_type = NULL;
    conn->authorization = NULL;
    conn->header = NULL;
    conn->header_len = 0;
    conn->resp = NULL;
    conn->resp_len = 0;
    conn->state = CONN_CLOSING;

    return conn;
}

void set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

void close_connection(struct connection *conn, int epoll_fd)
{
    if (conn->fd != -1) close(conn->fd);
    if (conn->req != NULL) free(conn->req);
    if (conn->method != NULL) free(conn->method);
    if (conn->url != NULL) free(conn->url);
    if (conn->host != NULL) free(conn->host);
    if (conn->user_agent != NULL) free(conn->user_agent);
    if (conn->content_type != NULL) free(conn->content_type);
    if (conn->authorization != NULL) free(conn->authorization);
    if (conn->header != NULL) free(conn->header);
    if (conn->resp != NULL) free(conn->resp);

    close(conn->fd);
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL);
}

static char *parse_header_field(const struct connection *conn, const char *field)
{
    size_t start, end, val_len;
    char *pos, *val;

    pos = strcasestr(conn->req, field);
    if (pos == NULL)
        return NULL;
    assert(pos >= conn->req);
    start = (pos - conn->req) + strlen(field);

    while (end < conn->req_len &&
        !(conn->req[end] == '\r' && conn->req[end + 1] == '\n'))
        end++;

    val_len = end - start + 1;
    val = malloc(val_len);
    memcpy(val, conn->req + start, val_len);
    val[val_len] = '\0';

    return val;
}

// returns position in conn->req where body starts, or -1 on error
static int parse_request(struct connection *conn)
{
    char *buf = conn->req;
    size_t len = conn->req_len;

    // shortest possible HTTP request line is 14 bytes ("GET / HTTP/1.1")
    if (len < 14) return -1;

    size_t i = 0;

    // parse method
    size_t method_start = i;
    while (i < len && buf[i] != ' ') {
        // ensure method is in all caps
        if (!isupper((unsigned char)buf[i])) return -1;
        i++;
    }
    if (i == method_start || i >= len) return -1;

    buf[i] = '\0';
    conn->method = &buf[method_start];
    i++;

    // parse url
    size_t url_start = i;
    while (i < len && buf[i] != ' ') {
        if (buf[i] == '\r' || buf[i] == '\n') return -1;
        i++;
    }
    if (i == url_start || i >= len) return -1;
    if (buf[url_start] != '/') return -1;

    buf[i] = '\0';
    conn->url = &buf[url_start];
    i++;

    // parse version
    if (i + 7 >= len) return -1;
    if (memcmp(&buf[i], "HTTP/1.1", 8) != 0) return -1;
    i += 8;

    // require CRLF
    if (i + 1 >= len || buf[i] != '\r' || buf[i + 1] != '\n') return -1;
    i += 2;

    // parse headers
    for (; i + 4 < len &&
        buf[i] != '\r' &&
        buf[i + 1] != '\n' &&
        buf[i + 2] != '\r' &&
        buf[i + 3] != '\n';
        i++)
    {
        char *header;
        size_t header_start = i;
        while (i < len && buf[i] != ':') i++;
        buf[i] = '\0';
        header = &buf[header_start];

        if (strcasecmp(header, "Host") == 0)
            conn->host = parse_header_field(conn, "Host: ");
        if (strcasecmp(header, "Content-Length") == 0)
            conn->content_length = (size_t)strtoimax(parse_header_field(conn, "Content-Length: "), NULL, 0);
        if (strcasecmp(header, "User-Agent") == 0)
            conn->user_agent = parse_header_field(conn, "User-Agent: ");
        if (strcasecmp(header, "Content-Type") == 0)
            conn->content_type = parse_header_field(conn, "Content-Type: ");
        if (strcasecmp(header, "Authorization") == 0)
            conn->authorization = parse_header_field(conn, "Authorization: ");
    }
    i += 4;

    return i;
}

void recv_req(struct connection *conn, int epoll_fd)
{
    assert(conn->state == CONN_READING);
    char buf[1024];
    ssize_t recvd;

    recvd = recv(conn->fd, buf, sizeof(buf), 0);
    if (recvd < 1) {
        if (recvd == -1)
            fprintf(stderr, "recv_req (recv) %d: %s\n",
                    conn->fd, strerror(errno));

        conn->state = CONN_CLOSING;
        return;
    }

    assert(recvd > 0);
    conn->req = malloc(conn->req_len + (size_t)recvd + 1);
    memcpy(conn->req + conn->req_len, buf, (size_t)recvd);
    conn->req_len += (size_t)recvd;
    conn->req[conn->req_len] = '\0';

    ssize_t req_body_pos = parse_request(conn);
    if (req_body_pos < 0) {
        fprintf(stderr, "recv_req (parse_request_line) invalid request\n");
        exit(EXIT_FAILURE);
    }

    printf("METHOD: %s\n", conn->method);
    printf("URL: %s\n", conn->url);
    conn->req += req_body_pos;
    printf("REQ:\n\n%s\n", conn->req);

    // assume request ends with \r\n\r\n and always respond the same way
    if (strstr(conn->req, "\r\n\r\n")) {
        const char *response = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, world!";
        conn->resp = malloc(conn->resp_len + strlen(response) + 1);
        memcpy(conn->resp, response, strlen(response));
        conn->resp_len += strlen(response);
        conn->state = CONN_WRITING;

        // switch to EPOLLOUT
        struct epoll_event ev = {0};
        ev.events = EPOLLOUT;
        ev.data.ptr = conn;
        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->fd, &ev);
    }
}

void send_resp(struct connection *conn)
{
    assert(conn->state == CONN_WRITING);
    ssize_t sent;

    sent = send(conn->fd, conn->resp, conn->resp_len, 0);
    if (sent < 1) {
        if (sent == -1)
            fprintf(stderr, "send_resp (send) %d: %s\n",
                    conn->fd, strerror(errno));

        conn->state = CONN_CLOSING;
        return;
    }

    conn->state = CONN_CLOSING;
}

// Thank u beej
int init_socket()
{
    int fd;
    struct addrinfo hints, *ai, *p;
    int yes = 1;
    int rv;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if ((rv = getaddrinfo(NULL, g_config.port, &hints, &ai)) != 0) {
        fprintf(stderr, "init_socket (getaddrinfo): %s\n", gai_strerror(rv));
        exit(EXIT_FAILURE);
    }

    for (p = ai; p != NULL; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) {
            continue;
        }

        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

        if (bind(fd, p->ai_addr, p->ai_addrlen) == -1) {
            close(fd);
            perror("init_socket (bind)");
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "init_socket (failed to bind)\n");
        exit(EXIT_FAILURE);
    }

    freeaddrinfo(ai);

    if (listen(fd, MAX_EVENTS) == -1) {
        perror("init_socket (listen)");
        exit(EXIT_FAILURE);
    }

    printf("Listening on port %s...\n", g_config.port);

    return fd;
}

static int fd_null = -1;

static void daemon_start()
{
    pid_t f;

    fd_null = open("/dev/null", O_RDWR, 0);
    if (fd_null == -1) {
        fprintf(stderr, "daemon_start (open fd_null)\n");
        exit(EXIT_FAILURE);
    }

    if ((f = fork()) == -1) {
        fprintf(stderr, "daemon_start (fork)\n");
        exit(EXIT_FAILURE);
    } else if (f != 0) {
        pid_t w;
        int status;

        if ((w = waitpid(f, &status, WNOHANG)) == -1) {
            fprintf(stderr, "daemon_start (waitpid)\n");
            exit(EXIT_FAILURE);
        } else if (w == 0) {
            exit(EXIT_SUCCESS);
        } else {
            exit(WEXITSTATUS(status));
        }
    }
}

void daemon_finish()
{
    if (fd_null == -1)
        return;

    if (setsid() == -1)
        fprintf(stderr, "daemon_finish (setsid)\n");

    if (dup2(fd_null, STDIN_FILENO) == -1)
        fprintf(stderr, "daemon_finish (dup2 stdin)\n");
    if (dup2(fd_null, STDOUT_FILENO) == -1)
        fprintf(stderr, "daemon_finish (dup2 stdout)\n");
    if (dup2(fd_null, STDERR_FILENO) == -1)
        fprintf(stderr, "daemon_finish (dup2 stderr)\n");

    if (fd_null > 2)
        close(fd_null);
}

static void print_usage(const char *pname)
{
    printf("USAGE:\t%s /path/to/root [Options...]\n\n", pname);
    printf("Options:\n\t--port <NUMBER> (default: %s)\n", g_config.port);
    printf("\t\tPort to listen on for connections.\n");
    printf("\t--daemon (default: false)\n"
           "\t\tDetach process from terminal and run in background.\n");
    printf("\t--no-keepalive\n"
           "\t\tDisable keepalive functionality.\n\n");
}

void parse_args(const int argc, char *argv[])
{
    int i;
    size_t len;

    if ((argc < 2) || (argc == 2 && strcmp(argv[1], "--help") == 0)) {
        print_usage(argv[0]);
        exit(EXIT_SUCCESS);
    }

    g_config.root_dir = strdup(argv[1]);
    len = strlen(g_config.root_dir);
    if (len == 0)
        fprintf(stderr, "Root directory cannot be empty\n");
    if (len > 1)
        if (g_config.root_dir[len - 1] == '/')
            g_config.root_dir[len - 1] = '\0';

    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0) {
            if (++i >= argc)
                fprintf(stderr, "Please provide a port number\n");
            g_config.port = argv[i];
        } else if (strcmp(argv[i], "--daemon") == 0) {
            g_config.daemonize = 1;
        } else if (strcmp(argv[i], "--no-keepalive") == 0) {
            g_config.keepalive = 0;
        }
    }
}

int main(int argc, char *argv[])
{
    printf("%s\n", PKG_NAME);
    struct sigaction sa;
    parse_args(argc, argv);
    int server_fd = init_socket();
    set_nonblocking(server_fd);

    if (g_config.daemonize)
        daemon_start();

    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("main (sigaction)");
        return 1;
    }

    if (g_config.daemonize)
        daemon_finish();

    int epoll_fd = epoll_create1(0);
    struct epoll_event ev = {0};
    ev.events = EPOLLIN;
    ev.data.fd = server_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &ev);

    struct epoll_event events[MAX_EVENTS];

    for (;;) {
        int n = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        for (int i = 0; i < n; i++) {
            if (events[i].data.fd == server_fd) {
                // accept new conn
                int client_fd = accept(server_fd, NULL, NULL);
                struct connection *conn = new_connection();
                conn->fd = client_fd;
                set_nonblocking(conn->fd);
                conn->state = CONN_READING;

                struct epoll_event client_ev = {0};
                client_ev.events = EPOLLIN;
                client_ev.data.ptr = conn;
                epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &client_ev);
            } else {
                struct connection *conn = events[i].data.ptr;
                if (conn->state == CONN_READING && (events[i].events & EPOLLIN)) {
                    recv_req(conn, epoll_fd);
                } else if (conn->state == CONN_WRITING && (events[i].events & EPOLLOUT)) {
                    send_resp(conn);
                }

                if (conn->state == CONN_CLOSING) {
                    close_connection(conn, epoll_fd);
                }
            }
        }
    }

    close(server_fd);
    close(epoll_fd);
    return 0;
}
