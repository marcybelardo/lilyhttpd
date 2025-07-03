/*
 * lilyhttpd
 * a simple lil' web server
 */

#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syslog.h>
#include <syslog.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/*
 * Defines and structs
 */

static const char PKG_NAME[] = "lilyhttpd v0.2.0";

#define MAX_EVENTS 1024
#define TIMEOUT_SECS 10

typedef enum {
    LDEBUG = 0,
    LINFO,
    LWARN,
    LERROR
} LogLevel;

static const char *log_level_names[] = {
    "DEBUG",
    "INFO",
    "WARN",
    "ERROR"
};

struct connection {
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
    char *if_modified_since;
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

struct mime_type {
    char *ext;
    char *type;
};

#define MIME_COUNT 27
static const struct mime_type mime_map[27] = {
    {"bin", "application/octet-stream"},
    {"bmp", "image/bmp"},
    {"css", "text/css"},
    {"gif", "image/gif"},
    {"htm", "text/html"},
    {"html", "text/html"},
    {"ico", "image/vnd.microsoft.icon"},
    {"jpeg", "image/jpeg"},
    {"jpg", "image/jpeg"},
    {"js", "text/javascript"},
    {"json", "application/json"},
    {"md", "text/markdown"},
    {"mjs", "text/javascript"},
    {"mp3", "audio/mpeg"},
    {"mp4", "video/mp4"},
    {"mpeg", "video/mpeg"},
    {"png", "image/png"},
    {"pdf", "application/pdf"},
    {"svg", "image/svg+xml"},
    {"ttf", "font/ttf"},
    {"txt", "text/plain"},
    {"wav", "audio/wav"},
    {"webm", "video/webm"},
    {"webp", "image/webp"},
    {"woff", "font/woff"},
    {"woff2", "font/woff2"},
    {"xml", "application/xml"},
};

/*
 * Globals
 */

static struct pollfd pfds[MAX_EVENTS];
static struct connection *conns[MAX_EVENTS];
static size_t conn_count = 0;
static const char *index_name = "index.html";
static const char *server_header = "Server: lilyhttpd";
static int running = 1;
static int server_fd = -1;
static char *root_dir = NULL;
static char *port = "8080";
static int daemonize = 0;
static int no_keepalive = 0;
static time_t now;
static LogLevel current_log_level = LDEBUG;
static int debug_mode = 0;
static FILE *log_file = NULL;
static int use_syslog = 0;

static void sigchld_handler(int s)
{
    (void)s;

    // waitpid() might overwrite errno, so we save and restore it:
    int saved_errno = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0);
    errno = saved_errno;
}

/*
 * Log Handling
 */

static void init_log(int enable_debug, const char *log_path, int enable_syslog, LogLevel level)
{
    debug_mode = enable_debug;
    current_log_level = level;
    use_syslog = enable_syslog;

    if (use_syslog)
        openlog("lilyhttpd", LOG_PID | LOG_NDELAY, LOG_DAEMON);

    if (log_path && !use_syslog) {
        log_file = fopen(log_path, "a");
        if (!log_file) {
            fprintf(stderr, "Could not open log file %s\n", log_path);
            log_file = stderr;
        }
    } else if (!debug_mode && !use_syslog) {
        log_file = stderr;
    }
}

static void log_msg(LogLevel level, const char *fmt, ...)
{
    if (level < current_log_level)
        return;

    va_list args;
    va_start(args, fmt);

    char timebuf[64] = {0};
    struct tm *tm_info = localtime(&now);
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm_info);

    if (debug_mode || log_file) {
        FILE *out = debug_mode ? stderr : log_file;
        fprintf(out, "[%s] %s: ", timebuf, log_level_names[level]);
        vfprintf(out, fmt, args);
        fprintf(out, "\n");
        fflush(out);
    }

    if (use_syslog) {
        int syslog_level = LINFO;
        switch (level) {
            case LDEBUG: syslog_level = LOG_DEBUG; break;
            case LINFO: syslog_level = LOG_INFO; break;
            case LWARN: syslog_level = LOG_WARNING; break;
            case LERROR: syslog_level = LOG_ERR; break;
        }

        vsyslog(syslog_level, fmt, args);
    }

    va_end(args);
}

static void close_log()
{
    if (log_file && log_file != stderr)
        fclose(log_file);
    if (use_syslog)
        closelog();
}

/*
 * Connection functions
 */

static void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
        return &(((struct sockaddr_in *)sa)->sin_addr);

    return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

static struct connection *new_connection()
{
    struct connection *conn = malloc(sizeof(struct connection));

    conn->req = NULL;
    conn->req_len = 0;
    conn->method = NULL;
    conn->url = NULL;
    conn->host = NULL;
    conn->content_length = 0;
    conn->user_agent = NULL;
    conn->content_type = NULL;
    conn->authorization = NULL;
    conn->if_modified_since = NULL;
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
static void close_connection(struct connection *conn, int client_fd, size_t i)
{
    if (client_fd != -1) close(client_fd);
    if (conn->req != NULL) free(conn->req);
    if (conn->header != NULL) free(conn->header);
    if (conn->resp_fd != -1) close(conn->resp_fd);
    if (conn->resp != NULL) free(conn->resp);

    pfds[i] = pfds[conn_count - 1];
    conn_count--;
}

static void keepalive_connection(struct connection *conn, int client_fd, size_t i)
{
    assert(conn->state == CONN_CLOSING);
    int tmpfd = client_fd;
    client_fd = -1;
    close_connection(conn, client_fd, i);
    client_fd = tmpfd;

    conn->req = NULL;
    conn->req_len = 0;
    conn->method = NULL;
    conn->url = NULL;
    conn->host = NULL;
    conn->content_length = 0;
    conn->user_agent = NULL;
    conn->content_type = NULL;
    conn->authorization = NULL;
    conn->if_modified_since = NULL;
    conn->keepalive = 0;
    conn->header = NULL;
    conn->header_len = 0;
    conn->header_only = 0;
    conn->resp_fd = -1;
    conn->resp = NULL;
    conn->resp_len = 0;

    conn->state = CONN_READING;
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

    return fd;
}


/*
 * Network Utils
 */

#define DATE_LEN 30
static char *rfc1123_date(char *dest, const time_t when)
{
    time_t when_copy = when;
    if (strftime(dest, DATE_LEN, "%a, %d %b %Y %H:%M:%S GMT", gmtime(&when_copy)) == 0)
        dest[0] = '\0';

    return dest;
}

static char *get_mime_type(const char *ext)
{
    for (size_t i = 0; i < MIME_COUNT; i++) {
        if (strcmp(ext, mime_map[i].ext) == 0)
            return mime_map[i].type;
    }

    return "application/octet-stream";
}

#define UPPER_HEX_OFFSET 55
#define LOWER_HEX_OFFSET 87
#define NUM_HEX_OFFSET 48

static inline int hex_to_num(char c)
{
    if (isupper(c))
        return c - UPPER_HEX_OFFSET;
    else if (isalpha(c))
        return c - LOWER_HEX_OFFSET;
    else
        return c - NUM_HEX_OFFSET;
}

static char *decode_url(char *url)
{
    size_t i, pos, len = strlen(url);
    char *out = malloc(len + 1);

    for (i = 0, pos = 0; i < len; i++) {
        if ((url[i] == '%') && (i + 2 < len)) {
            if (isxdigit(url[i + 1]) && isxdigit(url[i + 2])) {
                out[pos++] = hex_to_num(url[i + 1]) * 16 +
                            hex_to_num(url[i + 2]);
                i += 2;
            }
        } else {
            out[pos++] = url[i];
        }
    }
    out[pos] = '\0';

    return out;
}

static char *sanitize_url(char *const url)
{
    char *src = url;
    char *out;

    if (url[0] != '/')
        return NULL;

    out = src;
    while (*src) {
        // multi slashes should be collapsed into one slash
        // single dot dirs can be ignored
        // double dot dirs should be traversed, or treated as malicious

        if (*src != '/') {
            *out++ = *src++;
            continue;
        }

        // assuming current char is a slash
        // we start evaluating on the next char

        // keep skipping consecutive slashes
        if (*++src == '/')
            continue;

        // if we're out of slashes and not dealing with dot dirs
        // we can set the next char as a slash
        else if (*src != '.')
            *out++ = '/';

        // if the next char is a dot, check if it is a dot dir
        else if (*(src + 1) == '/')
            src++;

        // found a double dot dir
        else if (*(src + 1) == '.' && *(src + 2) == '/') {
            src += 2;

            // no previous directory to go to
            // so it's an illegal URL
            if (out == url)
                return NULL;

            // walk back to the last available directory
            else
                for (; *out != '/'; out--);
        }

        else
            *out++ = '/';
    }

    if (out == url)
        out++;
    *out = '\0';

    return url;
}

/*
 * Server Functions
 */

static void server_response(struct connection *conn, const int code,
                     const char *ename, const char *format, ...)
{
    char *reason, date[DATE_LEN];
    va_list va;

    va_start(va, format);
    vasprintf(&reason, format, va);
    va_end(va);

    rfc1123_date(date, now);

    log_msg(LINFO, "%d %s - %s %s HTTP/1.1",
            code, ename, conn->method, conn->url);

    conn->resp_len = asprintf(&(conn->resp),
        "<!DOCTYPE html><html><head><title>%d %s</title></head><body>\r\n"
        "<h1>%d %s</h1>\r\n"
        "%s\r\n"
        "<hr>\r\n"
        "<em>Server: %s [%s]</em>\r\n"
        "</body></html>\r\n",
        code,
        ename,
        code,
        ename,
        reason,
        PKG_NAME,
        date
    );
    free(reason);

    conn->header_len = asprintf(&(conn->header),
        "HTTP/1.1 %d %s\r\n"
        "Date: %s\r\n"
        "%s\r\n"
        "Accept-Ranges: bytes\r\n"
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
    char *target, *end, *decoded, *type_start, *type;
    char date[DATE_LEN], last_modified[DATE_LEN];
    // char absolute_path[PATH_MAX];
    struct stat filestat;

    if ((end = strchr(conn->url, '?')) != NULL)
        *end = '\0';

    // decode URL
    // free this!
    decoded = decode_url(conn->url);
    // ensure path safety
    if (!(sanitize_url(decoded))) {
        server_response(conn, 400, "Bad Request", "The URL you requested is invalid");
        goto clean;
    }

    if (conn->url[strlen(conn->url) - 1] == '/') {
        // if path ends with '/', get the index file
        (void)asprintf(&target, "%s%s%s", root_dir, decoded, index_name);
        if ((stat(target, &filestat) == -1) && (errno == ENOENT)) {
            server_response(conn, 404, "Not Found", "The URL you requested cannot be found");
            goto clean;
        }
    } else {
        (void)asprintf(&target, "%s%s", root_dir, decoded);
    }

    if ((type_start = strrchr(target, '.')) == NULL) {
        server_response(conn, 404, "Not Found", "The URL you requested cannot be found");
        goto clean;
    }
    type = get_mime_type(type_start + 1);

    conn->resp_fd = open(target, O_RDONLY | O_NONBLOCK);
    type = get_mime_type(strrchr(target, '.') + 1);
    free(decoded);
    free(target);

    if (conn->resp_fd == -1) {
        switch (errno) {
        case EACCES:
            server_response(conn, 403, "Forbidden", "You do not have permission to access this URL");
            return;
        case ENOENT:
            server_response(conn, 404, "Not Found", "The URL you requested cannot be found");
            return;
        default:
            server_response(conn, 500, "Internal Server Error",
                            "The URL you requested cannot be opened: %s", strerror(errno));
            return;
        }
    }

    // stat file
    if (fstat(conn->resp_fd, &filestat) == -1) {
        server_response(conn, 500, "Internal Server Error",
                        "fstat() failed: %s", strerror(errno));
        return;
    }
    // check for regular file
    if (!S_ISREG(filestat.st_mode)) {
        server_response(conn, 403, "Forbidden", "Not a regular file");
        return;
    }

    rfc1123_date(last_modified, filestat.st_mtim.tv_sec);

    if ((conn->if_modified_since) &&
        (strcmp(conn->if_modified_since, last_modified) == 0))
    {
        conn->header_len = asprintf(&(conn->header),
            "HTTP/1.1 304 Not Modified\r\n"
            "Date: %s\r\n"
            "%s\r\n"
            "Connection: %s\r\n"
            "\r\n",
            rfc1123_date(date, now),
            server_header,
            conn->keepalive ? "keep-alive" : "close"
        );
        conn->resp_len = 0;
        conn->resp_type = SERV_RESP;
        conn->header_only = 1;
        return;
    }

    log_msg(LINFO, "%s %s HTTP/1.1 [%s]",
            conn->method, conn->url, conn->user_agent);

    conn->resp_type = FILE_RESP;
    conn->resp_len = filestat.st_size;
    conn->header_len = asprintf(&(conn->header),
            "HTTP/1.1 200 OK\r\n"
            "Date: %s\r\n"
            "%s\r\n" // server
            "Connection: %s\r\n" // keepalive
            "Content-Length: %zu\r\n"
            "Content-Type: %s\r\n"
            "Last-Modified: %s\r\n"
            "\r\n",
            rfc1123_date(date, now),
            server_header,
            conn->keepalive ? "keep-alive" : "close",
            conn->resp_len,
            type,
            last_modified
    );

    return;

clean:
    if (decoded)
        free(decoded);
    if (target)
        free(target);
    return;
}

// static void parse_range_header(struct connection *conn, const char *field)
// {
//
// }

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

            if (no_keepalive) conn->keepalive = 0;
        }
        // else if (strcasecmp(current_value, "Range") == 0)
        //     parse_range_header(conn);
        else if (strcasecmp(current_header, "Host") == 0)
            conn->host = current_value;
        else if (strcasecmp(current_header, "User-Agent") == 0)
            conn->user_agent = current_value;
        else if (strcasecmp(current_header, "Content-Type") == 0)
            conn->content_type = current_value;
        else if (strcasecmp(current_header, "Authorization") == 0)
            conn->authorization = current_value;
        else if (strcasecmp(current_header, "If-Modified-Since") == 0)
            conn->if_modified_since = current_value;
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

/*
 * Response/Request Handlers
 */

static void recv_req(struct connection *conn, int client_fd)
{
    assert(conn->state == CONN_READING);
    char buf[1024];
    ssize_t recvd;

    recvd = recv(client_fd, buf, sizeof(buf), 0);
    if (recvd < 1) {
        if (recvd == -1)
            log_msg(LERROR, "recv_req (recv) %d: %s\n",
                    client_fd, strerror(errno));

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
}

static void send_resp(struct connection *conn, int client_fd)
{
    assert(conn->state == CONN_WRITING);
    ssize_t header_sent, resp_sent = 0;
    off_t offset = 0;

    assert(conn->header_len == strlen(conn->header));
    header_sent = send(client_fd, conn->header, conn->header_len, 0);
    if (header_sent < 1) {
        if (header_sent == -1)
            fprintf(stderr, "send_resp (send headers) %d: %s\n",
                    client_fd, strerror(errno));

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
            resp_sent = send(client_fd, conn->resp, conn->resp_len, 0);
            break;
        case FILE_RESP:
            resp_sent = sendfile(client_fd, conn->resp_fd, &offset, conn->resp_len);
            break;
    }
    if (resp_sent < 1) {
        if (resp_sent == -1)
            fprintf(stderr, "send_resp (send resp) %d: %s\n",
                    client_fd, strerror(errno));

        conn->state = CONN_CLOSING;
        return;
    }

    conn->state = CONN_CLOSING;
}

/*
 * System Processes
 */

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
    printf("\t--no-keepalive\n"
           "\t\tForce disable keepalive functionality.\n");
    printf("\t--debug\n"
           "\t\tEnable debug mode.\n\n");
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
            no_keepalive = 0;
        } else if (strcmp(argv[i], "--debug") == 0) {
            debug_mode = 1;
        }
    }
}

/*
 * Event Loop
 */

static void accept_conn(struct connection *conn)
{
    int client_fd;
    struct sockaddr_storage client_addr;
    socklen_t addr_len = sizeof(client_addr);
    char clientIP[INET6_ADDRSTRLEN];

    client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
    if (client_fd == -1) {
        log_msg(LERROR, "accept_conn() accept: %s",
                strerror(errno));
    }

    set_nonblocking(client_fd);
    pfds[conn_count].fd = client_fd;
    pfds[conn_count].events = POLLIN;
    conns[conn_count] = conn;
    conns[conn_count]->state = CONN_READING;
    conn_count++;

    log_msg(LINFO, "new connection from %s on socket %d",
            inet_ntop(client_addr.ss_family,
                      get_in_addr((struct sockaddr *)&client_addr),
                      clientIP, INET6_ADDRSTRLEN),
            client_fd);
}

static void server_process()
{
    int ret;

    pfds[0].fd = server_fd;
    pfds[0].events = POLLIN;
    conn_count = 1;

    for (;;) {
        ret = poll(pfds, conn_count, TIMEOUT_SECS * 1000);
        if (ret == -1) {
            perror("poll");
            exit(EXIT_FAILURE);
        }

        for (size_t i = 0; i < conn_count; i++) {
            if (pfds[i].revents & POLLIN) {
                if (pfds[i].fd == server_fd) {
                    struct connection *new_conn = new_connection();
                    accept_conn(new_conn);
                } else {
                    struct connection *conn = conns[i];
                    int client_fd = pfds[i].fd;

                    now = time(NULL);

                    if (conn->state == CONN_READING) {
                        recv_req(conn, client_fd);
                        if (conn->state == CONN_WRITING)
                            pfds[i].events = POLLOUT;
                    }

                    if (conn->state == CONN_CLOSING) {
                        if (conn->keepalive)
                            keepalive_connection(conn, client_fd, i);
                        else
                            close_connection(conn, client_fd, i);
                    }
                }
            } else if (pfds[i].revents & POLLOUT) {
                struct connection *conn = conns[i];
                int client_fd = pfds[i].fd;

                if (conn->state == CONN_WRITING) {
                    send_resp(conn, client_fd);
                }

                if (conn->state == CONN_CLOSING) {
                    if (conn->keepalive)
                        keepalive_connection(conn, client_fd, i);
                    else
                        close_connection(conn, client_fd, i);
                }
            }
        }
    }

    close(server_fd);
}

/*
 * Main
 */

int main(int argc, char *argv[])
{
    printf("%s\n", PKG_NAME);

    now = time(NULL);
    init_log(true, "lilyhttpd.log", false, LDEBUG);

    struct sigaction sa;

    parse_args(argc, argv);
    server_fd = init_socket();
    if (server_fd == -1) {
        fprintf(stderr, "main init_socket(): %s",
                strerror(errno));
        exit(EXIT_FAILURE);
    }
    set_nonblocking(server_fd);

    log_msg(LINFO, "Server running on port %s", port);

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

    if (running)
        server_process();

    close_log();

    return 0;
}
