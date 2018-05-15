#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>

#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <event2/event.h>

#define TYSCC_LOG(p, fmt, ...) \
    printf("[%s][%d]" fmt "\n", __func__, __LINE__, ##__VA_ARGS__)

static struct event_base *g_http_evt_base = NULL;
static struct event *g_http_timer_evt = NULL;

typedef struct
{
    int skfd;
    SSL *ssl_handle;
    SSL_CTX *ssl_ctx;
}HTTP_CONN_ST;

HTTP_CONN_ST * http_conn_create(void)
{
    HTTP_CONN_ST *conn = NULL;

    conn = malloc(sizeof(HTTP_CONN_ST));
    if (NULL == conn) {
        return NULL;
    }
    memset(conn, 0, sizeof(HTTP_CONN_ST));

    return conn;
}

void http_conn_destroy(HTTP_CONN_ST *conn)
{
    free(conn);
    conn = NULL;

    return;
}

int http_get_host(const char *hostname, unsigned int *ipaddr)
{
    int i;
    char    buf[1024];
    struct  hostent hostinfo,*phost;
    int     ret;

    ret = gethostbyname_r(hostname, &hostinfo, buf, sizeof(buf), &phost, &ret);
    if (ret < 0) {
        TYSCC_LOG(LOG_ERR, "ERROR:gethostbyname(%s) ret:%d", hostname, ret);
        return -1; 
    }

    TYSCC_LOG(LOG_ERR, "gethostbyname(%s) success:ret:%d", hostname, ret);
    if(phost)
        TYSCC_LOG(LOG_ERR, "name:%s, addrtype:%d(AF_INET:%d), len:%d",
                phost->h_name,phost->h_addrtype,
                AF_INET, phost->h_length);

    for(i = 0; hostinfo.h_aliases[i];i++)
        TYSCC_LOG(LOG_ERR, "alias is:%s",hostinfo.h_aliases[i]);
    for(i = 0;hostinfo.h_addr_list[i];i++) {
        //TYSCC_LOG(LOG_ERR, "host addr is:%s",inet_ntoa(*(struct in_addr*)hostinfo.h_addr_list[i]));
        //inet_ntop(AF_INET, hostinfo.h_addr_list[i], ip_buf, buf_len);
        //TYSCC_LOG(LOG_ERR, "ip:[%s]", ip_buf);
        *ipaddr = *(int *)hostinfo.h_addr_list[i];

        return 0;
    }

    return -1;
}       

int http_tcp_connect(const char *hostname, int port)
{
    unsigned int ipaddr = 0;
    char ip_buf[64] = {0};
    int error = -1, handle = -1;
    struct sockaddr_in server;

    if (http_get_host(hostname, &ipaddr) < 0) {
        TYSCC_LOG(LOG_ERR, "get host of [%s], failed.", hostname);
        return -1;
    }

    inet_ntop(AF_INET, &ipaddr, ip_buf, sizeof(ip_buf));
    TYSCC_LOG(LOG_ERR, "ip:[%s]", ip_buf);

    handle = socket(AF_INET, SOCK_STREAM, 0);
    if (handle < 0) {
        TYSCC_LOG(LOG_ERR, "create socket failed.");
        return -1;
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = ipaddr;
    bzero (&(server.sin_zero), 8);

    error = connect(handle, (struct sockaddr *)&server,
            sizeof(struct sockaddr));
    if (error < 0) {
        TYSCC_LOG(LOG_ERR, "connect to [%s](%s) failed.", hostname, ip_buf);
        goto error;
    }

    return handle;

error:
    if (handle > 0) {
        close(handle);
        handle = -1;
    }

    return -1;
}

int http_ssl_global_init(void)
{
    /* Register the error strings for libcrypto & libssl */
    SSL_load_error_strings ();

    /* Register the available ciphers and digests */
    SSL_library_init ();
    OpenSSL_add_all_algorithms();

    return 0;
}

void http_ssl_global_fini(void)
{
    /* Free ciphers and digests lists */
    EVP_cleanup();

    /* Free OpenSSL error strings */
    ERR_free_strings();

    return;
}

HTTP_CONN_ST * http_ssl_conn_creat(const char *hostname)
{
    HTTP_CONN_ST *conn = NULL;

    conn = http_conn_create();
    if (NULL == conn) {
        return NULL;
    }

    conn ->skfd = http_tcp_connect(hostname, 443);
    if (conn->skfd < 0) {
        goto error;
    }

    conn->ssl_ctx = SSL_CTX_new(SSLv23_client_method ());
    if (conn->ssl_ctx  == NULL) {
        ERR_print_errors_fp (stderr);
        TYSCC_LOG(LOG_ERR, "ssl ctx new failed.");
        goto error;
    }

    /* Create an SSL struct for the connection */
    conn->ssl_handle = SSL_new(conn->ssl_ctx);
    if (conn->ssl_handle == NULL) {
        ERR_print_errors_fp (stderr);
        TYSCC_LOG(LOG_ERR, "ssl new failed.");
        goto error;
    }

    /* Connect the SSL struct to our connection */
    if (!SSL_set_fd (conn->ssl_handle, conn->skfd)) {
        ERR_print_errors_fp (stderr);
        TYSCC_LOG(LOG_ERR, "ssl set fd failed.");
        goto error;
    }

    /* Initiate SSL handshake */
    if (SSL_connect (conn->ssl_handle) != 1) {
        ERR_print_errors_fp (stderr);
        TYSCC_LOG(LOG_ERR, "ssl connect failed.");
        goto error;
    }

    return conn;

error:
    if (conn) {
        if (conn->ssl_ctx) {
            //TODO:ssl resources release.
        }
        if (conn->skfd > 0) {
            close(conn->skfd);
            conn->skfd = -1;
        }
        http_conn_destroy(conn);
    }
    return NULL;
}

int http_ssl_write(HTTP_CONN_ST *conn, const char *text, int len)
{
    int ret = -1;

    printf("text = [%s]\n", text);
    if (!conn) {
        return -1;
    }

    ret = SSL_write (conn->ssl_handle, text, len);

    return ret;
}

char *http_ssl_read(HTTP_CONN_ST *conn)
{
    char *rc = NULL;
    int received = 0, count = 0;
    int buffer_size = 1024;
    int free_size = 0;

    if (!conn) {
        return NULL;
    }

    rc = malloc (buffer_size);
    while (1) {
        if (buffer_size - count <= 0) {
            buffer_size *= 2;
            rc = realloc (rc, buffer_size);
            free_size = buffer_size - count;
            memset(rc + count, 0, free_size);
        }
        received = SSL_read(conn->ssl_handle, rc + count, buffer_size - count);
        printf("[received = %d]\n", received);
        if (received > 0) {
            count += received;
        }
        if (received < buffer_size - count)
            break;
    }
    printf("buf=[%s]\n", rc);

    return rc;
}

#if 0
const char *post_data = "POST /smarthome-api/v1.1/gateway/signup HTTP/1.1\r\n"
"cache-control: no-cache\r\n"
"User-Agent: PostmanRuntime/7.1.1\r\n"
"Accept: */*\r\n"
"Host: apis.t2.5itianyuan.com\r\n"
"content-type: application/x-www-form-urlencoded\r\n"
"accept-encoding: gzip, deflate\r\n"
"content-length: 345\r\n"
"Connection: keep-alive\r\n"
"\r\n"

"gatewaySn=201703091158&macAddress=20-17-03-09-11-58&vendorId=HUADI&productId=GZ6200&hardwareVersion=20160608&softwareVersion=20160608&moduleList=%5B%7B%22moduleSn%22%3A%22MODULE-ZIGBEE-0001%22%2C%22vendorCode%22%3A%22HUADI%22%2C%22productCode%22%3A%22M1-001%22%2C%22moduleType%22%3A%22zigbee%22%2C%22macAddress%22%3A%2211-22-33-44-55-66%22%7D%5D\r\n\r\n";
#endif

static const char *g_http_post_header_fmt  = 
"POST %s HTTP/1.1\r\n"
"cache-control: no-cache\r\n"
"User-Agent: %s\r\n"
"Accept: */*\r\n"
"Host: %s\r\n"
"content-type: application/x-www-form-urlencoded\r\n"
"accept-encoding: gzip, deflate\r\n"
"content-length: %d\r\n"
"Connection: keep-alive\r\n"
"\r\n"
"%s" ;

int http_ssl_post()
{
    HTTP_CONN_ST *conn = NULL;
    char http_data[1024];

    conn = http_ssl_conn_creat("apis.t2.5itianyuan.com");

const char *post_data = "gatewaySn=201703091158&macAddress=20-17-03-09-11-58&vendorId=HUADI&productId=GZ6200&hardwareVersion=20160608&softwareVersion=20160608&moduleList=%5B%7B%22moduleSn%22%3A%22MODULE-ZIGBEE-0001%22%2C%22vendorCode%22%3A%22HUADI%22%2C%22productCode%22%3A%22M1-001%22%2C%22moduleType%22%3A%22zigbee%22%2C%22macAddress%22%3A%2211-22-33-44-55-66%22%7D%5D\r\n\r\n";

    snprintf(http_data, sizeof(http_data), g_http_post_header_fmt, 
        "/smarthome-api/v1.1/gateway/signup",
        "POSTMAN",
        "apis.t2.5itianyuan.com",
        strlen(post_data), post_data);

    http_ssl_write(conn, http_data, strlen(http_data));

    http_ssl_read(conn);

    return 0;
}

struct timeval g_timeout;
static void http_timer_cb(int fd, short kind, void *userp)
{

    //TYSCC_LOG(LOG_DEBUG, "------------------");

    evtimer_add(g_http_timer_evt, &g_timeout);

    return;
}

static int http_timer_init(void)
{
    g_http_timer_evt = evtimer_new(g_http_evt_base, http_timer_cb, NULL);
	if (NULL == g_http_timer_evt) {
		TYSCC_LOG(LOG_ERR, "event new failed.\n");
        return -1;
	}
    g_timeout.tv_sec = 1;
    g_timeout.tv_usec = 0;

    evtimer_add(g_http_timer_evt, &g_timeout);

    return 0;
}

void *http_worker(void *args)
{
    int ret = -1;

    g_http_evt_base = event_base_new();
    if (!g_http_evt_base) {
        return NULL;
    }

    http_timer_init();

    ret = event_base_dispatch(g_http_evt_base);
    if (ret != 0) {
        TYSCC_LOG(LOG_ERR, "event_base_dispatch error:%d", ret);
        perror("event_base_dispatch");
    }

    return NULL;
}

int main(void)
{
    pthread_t tid;

    http_ssl_global_init();

    pthread_create(&tid, NULL, http_worker, NULL);

    http_ssl_post();

    while (1) {
        sleep(1);
    }

    http_ssl_global_fini();

    return 0;
}
