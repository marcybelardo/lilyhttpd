/*
 * lilyhttpd
 * a simple lil' web server
 */

#include <asm-generic/errno-base.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static const char PKG_NAME[] = "lilyhttpd v0.0.1";

#define MAX_EVENTS 1024

static void sigchld_handler(int s)
{
    (void)s;

    // waitpid() might overwrite errno, so we save and restore it:
    int saved_errno = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0);
    errno = saved_errno;
}

static const char *index_name = "index.html";
static const char *server_header = "Server: lilyhttpd";
static char *root_dir = NULL;
static char *port = "8080";
static int daemonize = 0;
static int force_keepalive = 0;
static time_t now;

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
    int keepalive;

    char *header;
    size_t header_len;
    int header_only;

    enum {
        SERV_RESP,
        FILE_RESP
    } resp_type;
    int resp_fd;
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
    conn->keepalive = 0;
    conn->header = NULL;
    conn->header_len = 0;
    conn->header_only = 0;
    conn->resp_type = SERV_RESP;
    conn->resp_fd = -1;
    conn->resp = NULL;
    conn->resp_len = 0;
    conn->state = CONN_CLOSING;

    return conn;
}

static void set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/*
 * A lot of info fields (e.g. host, user_agent) are char pointers
 * pulled from conn->req so we just have to ensure that all that
 * data exists and is freed along with conn->req
 */
static void close_connection(struct connection *conn, int epoll_fd)
{
    if (conn->fd != -1) close(conn->fd);
    if (conn->req != NULL) free(conn->req);
    if (conn->header != NULL) free(conn->header);
    if (conn->resp_fd != -1) close(conn->resp_fd);
    if (conn->resp != NULL) free(conn->resp);

    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL);
}

#define DATE_LEN 30
static char *rfc1123_date(char *dest, const time_t when)
{
    time_t when_copy = when;
    if (strftime(dest, DATE_LEN, "%a, %d %b %Y %H:%M:%S GMT", gmtime(&when_copy)) == 0)
        dest[0] = '\0';

    return dest;
}

static void server_response(struct connection *conn, const int code,
                     const char *ename, const char *format, ...)
{
    char *reason, date[DATE_LEN];
    va_list va;

    va_start(va, format);
    vasprintf(&reason, format, va);
    va_end(va);

    rfc1123_date(date, now);

    conn->resp_len = asprintf(&(conn->resp),
        "<!DOCTYPE html><html><head><title>%d %s</title></head><body>\n"
        "<h1>%d %s</h1>\n"
        "<hr>\n"
        "%s\n"
        "</body></html>\n",
        code, ename, code, ename, reason);
    free(reason);

    conn->header_len = asprintf(&(conn->header),
        "HTTP/1.1 %d %s\r\n"
        "Date: %s\r\n"
        "%s\r\n"
        "Connection: %s\r\n"
        "Content-Length: %zu\r\n"
        "Content-Type: text/html; charset=UTF-8\r\n"
        "\r\n",
        code,
        ename,
        date,
        server_header,
        conn->keepalive ? "keep-alive" : "close",
        conn->resp_len
    );

    conn->resp_type = SERV_RESP;
}

static void process_get(struct connection *conn)
{
    char *target, *end;
    char date[DATE_LEN];
    struct stat filestat;

    if ((end = strchr(conn->url, '?')) != NULL)
        *end = '\0';

    if (conn->url[strlen(conn->url) - 1] == '/') {
        // if path ends with '/', get the index file
        (void)asprintf(&target, "%s%s%s", root_dir, conn->url, index_name);
        if ((stat(target, &filestat) == -1) && (errno == ENOENT)) {
            free(target);
            server_response(conn, 404, "Not Found", "The URL you requested cannot be found");
        }
    } else {
        (void)asprintf(&target, "%s%s", root_dir, conn->url);
    }

    conn->resp_fd = open(target, O_RDONLY | O_NONBLOCK);
    free(target);

    if (conn->resp_fd == -1) {
        switch (errno) {
            case EACCES:
                server_response(conn, 403, "Forbidden", "You do not have permission to access this URL");
                break;
            case ENOENT:
                server_response(conn, 404, "Not Found", "The URL you requested cannot be found");
                break;
            default:
                server_response(conn, 500, "Internal Server Error",
                                "The URL you requested cannot be opened: %s", strerror(errno));
        }
    }

    conn->resp_len = filestat.st_size;
    conn->header_len = asprintf(&(conn->header),
            "HTTP/1.1 200 OK\r\n"
            "Date: %s\r\n"
            "%s\r\n" // server
            "Connection: %s\r\n" // keepalive
            "Content-Length: %zu\r\n"
            "Content-Type: %s\r\n"
            "\r\n",
            rfc1123_date(date, now),
            server_header,
            conn->keepalive ? "keep-alive" : "close",
            conn->resp_len,
            "text/html; charset=UTF-8");
    conn->resp_type = FILE_RESP;
}

/*
 * Returns the number of bytes parsed in the request up to the request body
 * or -1 on error
 */
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

    do {
        char *current_header;
        size_t header_start = i;
        for (; i < len && buf[i] != ':'; i++);
        buf[i] = '\0';
        current_header = &buf[header_start];
        i += 2;

        char *current_value;
        size_t value_start = i;
        for (; i + 2 < len && buf[i] != '\r' && buf[i + 1] != '\n'; i++);
        buf[i] = '\0';
        current_value = &buf[value_start];
        i += 2;

        if (strcasecmp(current_header, "Connection") == 0) {
            if (strcasecmp(current_value, "keep-alive") == 0)
                conn->keepalive = 1;
            else if (strcasecmp(current_value, "close") == 0)
                conn->keepalive = 0;

            if (force_keepalive) conn->keepalive = 1;
        }
        else if (strcasecmp(current_header, "Host") == 0)
            conn->host = current_value;
        else if (strcasecmp(current_header, "User-Agent") == 0)
            conn->user_agent = current_value;
        else if (strcasecmp(current_header, "Content-Type") == 0)
            conn->content_type = current_value;
        else if (strcasecmp(current_header, "Authorization") == 0)
            conn->authorization = current_value;
        else if (strcasecmp(current_header, "Content-Length") == 0) {
            conn->content_length = atol(current_value);
        }
    } while (i + 4 <= len &&
        buf[i] != '\r' &&
        buf[i + 1] != '\n' &&
        buf[i + 2] != '\r' &&
        buf[i + 3] != '\n');

    // we count two more bytes because the header parsing jumps two bytes
    // after successfully parsing every header, so this jump puts us
    // right at the start of the request body
    i += 2;
    return i;
}

static void recv_req(struct connection *conn, int epoll_fd)
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

    ssize_t bytes_parsed = parse_request(conn);
    if (bytes_parsed < 0) {
        server_response(conn, 400, "Bad Request", "Can't parse request");
    }

    if (strcmp(conn->method, "GET") == 0)
        process_get(conn);
    else if (strcmp(conn->method, "HEAD") == 0) {
        conn->header_only = 1;
        process_get(conn);
    } else {
        server_response(conn, 501, "Not Implemented",
                        "Server does not implement method '%s'", conn->method);
    }

    conn->state = CONN_WRITING;

    // switch to EPOLLOUT
    struct epoll_event ev = {0};
    ev.events = EPOLLOUT;
    ev.data.ptr = conn;
    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->fd, &ev);
}

static void send_resp(struct connection *conn)
{
    assert(conn->state == CONN_WRITING);
    ssize_t header_sent, resp_sent = 0;

    assert(conn->header_len == strlen(conn->header));
    header_sent = send(conn->fd, conn->header, conn->header_len, 0);
    if (header_sent < 1) {
        if (header_sent == -1)
            fprintf(stderr, "send_resp (send headers) %d: %s\n",
                    conn->fd, strerror(errno));

        conn->state = CONN_CLOSING;
        return;
    }
    if (conn->header_only) {
        conn->state = CONN_CLOSING;
        return;
    }

    switch (conn->resp_type) {
        case SERV_RESP:
            assert(conn->resp_len == strlen(conn->resp));
            resp_sent = send(conn->fd, conn->resp, conn->resp_len, 0);
            break;
        case FILE_RESP:
            resp_sent = sendfile(conn->fd, conn->resp_fd, NULL, conn->resp_len);
            break;
    }
    if (resp_sent < 1) {
        if (resp_sent == -1)
            fprintf(stderr, "send_resp (send resp) %d: %s\n",
                    conn->fd, strerror(errno));

        conn->state = CONN_CLOSING;
        return;
    }

    conn->state = CONN_CLOSING;
}

/*
 * Returns the file descriptor to the server listener
 * thank u beej
 */
static int init_socket()
{
    int fd;
    struct addrinfo hints, *ai, *p;
    int yes = 1;
    int rv;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if ((rv = getaddrinfo(NULL, port, &hints, &ai)) != 0) {
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

    printf("Listening on port %s...\n", port);

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

static void daemon_finish()
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
    printf("Options:\n\t--port <NUMBER> (default: %s)\n", port);
    printf("\t\tPort to listen on for connections.\n");
    printf("\t--daemon\n"
           "\t\tDetach process from terminal and run in background.\n");
    printf("\t--[no-]keepalive\n"
           "\t\tEnable or disable keepalive functionality.\n\n");
}

static void parse_args(const int argc, char *argv[])
{
    int i;
    size_t len;

    if ((argc < 2) || (argc == 2 && strcmp(argv[1], "--help") == 0)) {
        print_usage(argv[0]);
        exit(EXIT_SUCCESS);
    }

    root_dir = strdup(argv[1]);
    len = strlen(root_dir);
    if (len == 0)
        fprintf(stderr, "Root directory cannot be empty\n");
    if (len > 1)
        if (root_dir[len - 1] == '/')
            root_dir[len - 1] = '\0';

    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0) {
            if (++i >= argc)
                fprintf(stderr, "Please provide a port number\n");
            port = argv[i];
        } else if (strcmp(argv[i], "--daemon") == 0) {
            daemonize = 1;
        } else if (strcmp(argv[i], "--no-keepalive") == 0) {
            force_keepalive = 0;
        } else if (strcmp(argv[i], "--keepalive") == 0) {
            force_keepalive = 1;
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

    if (daemonize)
        daemon_start();

    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("main (sigaction)");
        return 1;
    }

    if (daemonize)
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
                now = time(NULL);
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
