/*
 * marigold
 * a simple lil' web server
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
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

static const char PKG_NAME[] = "marigold v0.0.1";

#define MAX_EVENTS 1024

#define READ_BUF_SIZE 4096
#define WRITE_BUF_SIZE 4096

void sigchld_handler(int s)
{
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

enum conn_state {
    CONN_READING,
    CONN_WRITING,
    CONN_CLOSING
};

struct connection {
    int fd;
    enum conn_state state;

    char read_buf[READ_BUF_SIZE];
    size_t read_pos;

    char write_buf[WRITE_BUF_SIZE];
    size_t write_pos;
    size_t write_len;

};

void set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

void close_conn(struct connection *conn, int epoll_fd)
{
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL);
    close(conn->fd);
    free(conn);
}

void handle_read(struct connection *conn, int epoll_fd)
{
    assert(conn->state == CONN_READING);

    ssize_t n = read(conn->fd, conn->read_buf + conn->read_pos, READ_BUF_SIZE - conn->read_pos);
    if (n <= 0) {
        conn->state = CONN_CLOSING;
        return;
    }

    conn->read_pos += n;

    // assume request ends with \r\n\r\n and always respond the same way
    if (strstr(conn->read_buf, "\r\n\r\n")) {
        const char *response = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, world!";
        conn->write_len = strlen(response);
        memcpy(conn->write_buf, response, conn->write_len);
        conn->write_pos = 0;
        conn->state = CONN_WRITING;

        // switch to EPOLLOUT
        struct epoll_event ev = {0};
        ev.events = EPOLLOUT;
        ev.data.ptr = conn;
        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->fd, &ev);
    }
}

void handle_write(struct connection *conn, int epoll_fd)
{
    assert(conn->state == CONN_WRITING);

    ssize_t n = write(conn->fd, conn->write_buf + conn->write_pos, conn->write_len - conn->write_pos);
    if (n <= 0) {
        conn->state = CONN_CLOSING;
        return;
    }

    conn->write_pos += n;
    if (conn->write_pos == conn->write_len) {
        conn->state = CONN_CLOSING;

        // to support keepalive, switch back to reading
    }
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
        fprintf(stderr, "[ERROR]: init_socket (getaddrinfo): %s\n", gai_strerror(rv));
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
                set_nonblocking(client_fd);

                struct connection *conn = calloc(1, sizeof(struct connection));
                conn->fd = client_fd;
                conn->state = CONN_READING;

                struct epoll_event client_ev = {0};
                client_ev.events = EPOLLIN;
                client_ev.data.ptr = conn;
                epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &client_ev);
            } else {
                struct connection *conn = events[i].data.ptr;
                if (conn->state == CONN_READING && (events[i].events & EPOLLIN)) {
                    handle_read(conn, epoll_fd);
                } else if (conn->state == CONN_WRITING && (events[i].events & EPOLLOUT)) {
                    handle_write(conn, epoll_fd);
                }

                if (conn->state == CONN_CLOSING) {
                    close_conn(conn, epoll_fd);
                }
            }
        }
    }

    close(server_fd);
    close(epoll_fd);
    return 0;
}
