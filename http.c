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
#include <fcntl.h>

#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <event2/event.h>
#include <event2/util.h>
#include <event2/dns.h>

#define TYSCC_LOG(p, fmt, ...) \
    printf("[%s][%d]" fmt "\n", __func__, __LINE__, ##__VA_ARGS__)

static struct event_base *g_http_evt_base = NULL;
static struct event *g_http_timer_evt = NULL;
struct evdns_base * g_http_evdns_base = 0; //TODO:need a lock?

typedef struct
{
    char hostname[256];
    int port;
    int skfd;
    SSL *ssl_handle;
    SSL_CTX *ssl_ctx;
    struct event *ssl_evt;
    struct evdns_base *evdns_base;
    char http_data[1024];
}HTTP_CONN_ST;

int http_ssl_write(HTTP_CONN_ST *conn, const char *text, int len);
char *http_ssl_read(HTTP_CONN_ST *conn);
static int http_tcp_connect(HTTP_CONN_ST *conn, unsigned int ipaddr);

HTTP_CONN_ST * http_conn_create(const char *hostname, int port)
{
    HTTP_CONN_ST *conn = NULL;

    conn = malloc(sizeof(HTTP_CONN_ST));
    if (NULL == conn) {
        return NULL;
    }
    memset(conn, 0, sizeof(HTTP_CONN_ST));
    
    snprintf(conn->hostname, sizeof(conn->hostname), "%s", hostname);
    conn->port = port;

    return conn;
}

void http_conn_destroy(HTTP_CONN_ST *conn)
{
    free(conn);
    conn = NULL;

    return;
}

struct evdns_base * http_setup_evdns_base(struct event_base *base)
{
    if(g_http_evdns_base) {
        return g_http_evdns_base;
    } else {
        struct evdns_base * dnsbase = 0;
#if defined(_WIN32)
        dnsbase = evdns_base_new(base, 0);
        evdns_base_nameserver_ip_add(dnsbase, "8.8.8.8");
#elif defined(ANDROID)
        dnsbase = evdns_base_new(base, 0);
        {
            int ret = 0;
            int contains_default = 0;
            char buf[PROP_VALUE_MAX];
            ret = __system_property_get("net.dns1", buf);
            if(ret >= 7)
            {
                if(!strncmp("8.8.8.8", buf, 7)) contains_default = 1;
                evdns_base_nameserver_ip_add(dnsbase, buf);
            }
            ret = __system_property_get("net.dns2", buf);
            if(ret >= 7)
            {
                if(!strncmp("8.8.8.8", buf, 7)) contains_default = 1;
                evdns_base_nameserver_ip_add(dnsbase, buf);
            }
            if(!contains_default)
            {
                evdns_base_nameserver_ip_add(dnsbase, "8.8.8.8");
            }
        }
#else
        dnsbase = evdns_base_new(base, 1);
#endif
        printf(" dns server count : %d\n", evdns_base_count_nameservers(dnsbase));

        g_http_evdns_base = dnsbase;
        return dnsbase;
    }
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
        TYSCC_LOG(LOG_ERR, "alias is:%s", hostinfo.h_aliases[i]);
    for(i = 0; hostinfo.h_addr_list[i]; i++) {
        //TYSCC_LOG(LOG_ERR, "host addr is:%s",inet_ntoa(*(struct in_addr*)hostinfo.h_addr_list[i]));
        //inet_ntop(AF_INET, hostinfo.h_addr_list[i], ip_buf, buf_len);
        //TYSCC_LOG(LOG_ERR, "ip:[%s]", ip_buf);
        *ipaddr = *(int *)hostinfo.h_addr_list[i];

        return 0;
    }

    return -1;
}

static void http_evdns_callback(int errcode, struct evutil_addrinfo *addr, void *arg)
{
    char ip[128];
    const char *s = NULL;
    struct evutil_addrinfo *ai;
    HTTP_CONN_ST *conn = NULL;
    unsigned int ipaddr = 0;

    conn = (HTTP_CONN_ST *)arg;

    if (errcode) {
        TYSCC_LOG(LOG_ERR, "%s -> %s\n", conn->hostname, evutil_gai_strerror(errcode));
        return;
    }

    TYSCC_LOG(LOG_DEBUG, "dns resolved,hostname - %s, ip :\n", conn->hostname);
    for (ai = addr; ai; ai = ai->ai_next) {
        if (ai->ai_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)ai->ai_addr;
            s = evutil_inet_ntop(AF_INET, &sin->sin_addr, ip, 128);
            ipaddr = sin->sin_addr.s_addr;
        } else if (ai->ai_family == AF_INET6) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ai->ai_addr;
            s = evutil_inet_ntop(AF_INET6, &sin6->sin6_addr, ip, 128);
        }
    }

    if(s) {
        TYSCC_LOG(LOG_DEBUG, "  %s(%X)\n", s, ipaddr);
        http_tcp_connect(conn, ipaddr);
    }

    /*
    if(addr) {
        evutil_freeaddrinfo(addr);
        addr = NULL;
    }
    */

    return;
}

int http_get_host_async(HTTP_CONN_ST *conn)
{
    struct evutil_addrinfo hints;
    struct evdns_getaddrinfo_request *req;

    conn->evdns_base = http_setup_evdns_base(g_http_evt_base);
    if (!conn->evdns_base) {
        TYSCC_LOG(LOG_ERR, "evdns setup error.");
        return -1; 
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = EVUTIL_AI_CANONNAME;
    #if 0
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    #else
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    #endif

    req = evdns_getaddrinfo(conn->evdns_base, conn->hostname, NULL ,
            &hints, http_evdns_callback, (void*)conn);
    if (req == NULL) {
        TYSCC_LOG(LOG_ERR, "[request for %s returned immediately]\n", conn->hostname);
        return -1;
    }

    return 0;
}

#if 0
#define IP_LEN       (32)
#define IP_COUNT_MAX (5)

typedef struct {                                   
    char host[64];
    char ip[IP_COUNT_MAX][IP_LEN];   
    int count;
}IP_LIST_ST;


void http_dns_callback(void* arg, int status, int timeouts, struct hostent* hptr)
{
    int i = 0;
    char **pptr = NULL;
    IP_LIST_ST *ips = NULL;

    if (NULL == arg) {
        return;
    }

    if(status != ARES_SUCCESS) {
        printf("lookup failed: %d\n", status);
        return;
    }

    ips = (IP_LIST_ST *)arg;

    pptr=hptr->h_addr_list;  
    for(i = 0; *pptr != NULL && i < IP_COUNT_MAX; pptr++, i++){
        inet_ntop(hptr->h_addrtype, *pptr, ips->ip[i], IP_LEN);
        printf("h_addr:%s\n", ips->ip[i]);
        ips->count++;
    }

    return;
}

void main_loop(ares_channel channel)
{
    int nfds, count;
    fd_set readers, writers;
    struct timeval tv, *tvp;
    while (1) {
        FD_ZERO(&readers);
        FD_ZERO(&writers);
        nfds = ares_fds(channel, &readers, &writers);
        if (nfds == 0)
            break;
        tvp = ares_timeout(channel, NULL, &tv);       
        count = select(nfds, &readers, &writers, NULL, tvp);
        ares_process(channel, &readers, &writers);
    }
}


int http_get_host_async(const char *hostname)
{
    int ret = -1;
    
    ares_channel ares_ch; 

    ret = ares_init(&ares_ch);
    if (ret != ARES_SUCCESS) {
        TYSCC_LOG(LOG_ERR, "ares init failed.");
        return -1;
    }

    IP_LIST_ST ips;
    //ares_set_servers_csv(channel, "114.114.114.114");
    ares_gethostbyname(ares_ch, hostname, AF_INET, http_dns_callback, (void *)&ips);

    nfds = ares_fds(channel, &readers, &writers);
     
    return 0;
}
#endif

int http_ssl_connect(HTTP_CONN_ST *conn);

static void http_conn_cb(int fd, short event, void *arg)
{
    int iRet = -1;
	int error = 0;
	int len   = sizeof(error);
    HTTP_CONN_ST *conn = NULL;

    conn = (HTTP_CONN_ST *)arg;
    TYSCC_LOG(LOG_DEBUG, "conn(0x%X) evt, fd:%d, skfd:%d, event:%d", 
            (unsigned int)conn, fd, conn->skfd, event);

    if (!(event & EV_WRITE)) {
        return;
    }
    
    iRet = getsockopt(conn->skfd, 
            SOL_SOCKET, 
            SO_ERROR, 
            &error, 
            (socklen_t *)&len);
    if (0 != iRet || 0 != error) {
        TYSCC_LOG(LOG_ERR, "EPOLL get EPOLLOUT but connect UnSuccess! errno=%d", errno);
        return;
    }

    TYSCC_LOG(LOG_ERR, "Server Connect Success!");

    http_ssl_connect((HTTP_CONN_ST *)arg);

    return;
}

#define HTTP_DNS_ASYNC 1

int http_request_start(HTTP_CONN_ST *conn)
{
    #ifdef HTTP_DNS_ASYNC
    if (http_get_host_async(conn) < 0) {
    #else
    unsigned int ipaddr = 0;

    //TODO: can create a cache
    if (http_get_host(conn->hostname, &ipaddr) < 0) {
    #endif
        TYSCC_LOG(LOG_ERR, "get host of [%s], failed.", conn->hostname);
        return -1;
    }
    #ifdef HTTP_DNS_ASYNC
    #else
    http_tcp_connect(conn, ipaddr);
    #endif

    return 0;
}

static int http_tcp_connect(HTTP_CONN_ST *conn, unsigned int ipaddr)
{
    int error = -1, handle = -1;
    struct sockaddr_in server;

    handle = socket(AF_INET, SOCK_STREAM, 0);
    if (handle < 0) {
        TYSCC_LOG(LOG_ERR, "create socket failed.");
        return -1;
    }
    //evutil_make_socket_nonblocking(handle);
    conn->skfd = handle;
    TYSCC_LOG(LOG_DEBUG, "conn(%08X), skfd:%d", (unsigned int)conn, conn->skfd);

    server.sin_family = AF_INET;
    server.sin_port = htons(conn->port);
    server.sin_addr.s_addr = ipaddr;
    bzero (&(server.sin_zero), 8);

    fcntl(handle, F_SETFL, O_NONBLOCK);
    TYSCC_LOG(LOG_DEBUG, "conn(%08X), skfd:%d", (unsigned int)conn, conn->skfd);

    error = connect(handle, (struct sockaddr *)&server, sizeof(struct sockaddr));
    if (error < 0) {
        if(EINPROGRESS != errno) {
            TYSCC_LOG(LOG_ERR, "connect to [%s](%X) failed. errno:%d", conn->hostname, ipaddr, errno);
            goto error;
        } else {
            TYSCC_LOG(LOG_DEBUG, "connect(skfd=%d) in process", handle);
        }
    }
    TYSCC_LOG(LOG_DEBUG, "conn(%08X), skfd:%d", (unsigned int)conn, conn->skfd);

    struct event *sk_conn_evt = NULL;
    sk_conn_evt = event_new(g_http_evt_base, handle, EV_WRITE | /* EV_PERSIST | */EV_ET, http_conn_cb, conn); 
    if (sk_conn_evt == NULL) {
        TYSCC_LOG(LOG_DEBUG, "event new failed");
        goto error;
    }

    event_add(sk_conn_evt, NULL);

    conn->ssl_evt = sk_conn_evt; 
    TYSCC_LOG(LOG_DEBUG, "conn(%08X), skfd:%d", (unsigned int)conn, conn->skfd);

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

    sleep(1); //TODO: need wait dns_base_is on dispatch!!

    conn = http_conn_create(hostname, 443);
    if (NULL == conn) {
        return NULL;
    }

    if (http_request_start(conn) < 0) {
    }

    return conn;
}

static int http_ssl_do_connect(HTTP_CONN_ST *conn)
{
    int ret = -1;
    int ret_err = -1;

    /* Initiate SSL handshake */
    ret = SSL_connect (conn->ssl_handle);
    if (ret < 0) {
        ERR_print_errors_fp (stderr);
        TYSCC_LOG(LOG_ERR, "ssl connect failed. errno:%d", errno);
        ret_err = SSL_get_error(conn->ssl_handle, ret);
        if (ret_err == SSL_ERROR_WANT_READ) {
            TYSCC_LOG(LOG_DEBUG, "ssl connect not compeleed.reed reconned.[%d:%d], ", 
                    ret_err, SSL_ERROR_WANT_READ);
            return SSL_ERROR_WANT_READ;
        } else {
            char acBuf[256];
            TYSCC_LOG(LOG_ERR, "Connected Failed.");
            //SSL_ShowCerts(conn->ssl_handle, acBuf, sizeof(acBuf));
            //TYSCC_LOG(LOG_ERR, "%s", acBuf);
            return -1;
        }
    } 

    TYSCC_LOG(LOG_ERR, "Connected Success. with %s encryption\n", SSL_get_cipher(conn->ssl_handle));

    return 0;
}


static void http_ssl_read_cb(int fd, short event, void *arg)
{
    HTTP_CONN_ST *conn = NULL;

    TYSCC_LOG(LOG_DEBUG, "ssl read evt handle. event:%d.", event);
    conn = (HTTP_CONN_ST *)arg;

    if (event & EV_READ) {
        TYSCC_LOG(LOG_DEBUG, "ssl write evt.");
    }

    if (event & EV_READ) {
        char buf[4096] = {0};
        int ret = -1;
        int ret_err = -1;
        //do {
            memset(buf, 0, sizeof(buf));
            ret = SSL_read(conn->ssl_handle, buf, sizeof(buf));
            TYSCC_LOG(LOG_DEBUG, "ssl read evt handle. errno:%d.", errno);
            ret_err = SSL_get_error(conn->ssl_handle, ret);
        //} while(errno == EAGAIN);
        //} while (ret_err == SSL_ERROR_WANT_READ);
        TYSCC_LOG(LOG_ERR, "buf[%s].ret_err[%d]", buf, ret_err);
    }
    
    return;
}

static void http_ssl_conn_cb(int fd, short event, void *arg)
{
    HTTP_CONN_ST *conn = NULL;

    TYSCC_LOG(LOG_DEBUG, "ssl conn success, event:%d", event);
    
    conn = (HTTP_CONN_ST *)arg;

    if (!(event & EV_READ)) {
        return;
    }

    /* NB:http_ssl_do_connect 是必须的，因为SSL_connect可能并没有真正的完成 !!!!!!!! */
    if (http_ssl_do_connect(conn) != 0) {
        TYSCC_LOG(LOG_DEBUG, "ssl connect not complete, skip.");
        return;
    }

    http_ssl_write(conn, conn->http_data, strlen(conn->http_data));
    event_del(conn->ssl_evt);

    event_assign(conn->ssl_evt, g_http_evt_base, conn->skfd, EV_READ | EV_PERSIST | EV_ET, http_ssl_read_cb, (void *)conn);
    event_add(conn->ssl_evt, NULL);

    return;
}

int http_ssl_connect(HTTP_CONN_ST *conn)
{

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

    http_ssl_do_connect(conn);

    event_assign(conn->ssl_evt, g_http_evt_base, conn->skfd, EV_READ | EV_PERSIST | EV_ET, http_ssl_conn_cb, (void *)conn);
    event_add(conn->ssl_evt, NULL);

    return 0;

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
    return -1;
}

int http_ssl_write(HTTP_CONN_ST *conn, const char *text, int len)
{
    int ret = -1;

    printf("text = [%s]\n", text);
    if (!conn) {
        return -1;
    }

    ret = SSL_write (conn->ssl_handle, text, len);
    printf("ret = [%d] errno:%d\n", ret, errno);


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
        if (received < 0) {
            TYSCC_LOG(LOG_DEBUG, "errno:%d", errno);
            /*
            if (errno == EAGAIN) {
                continue;
            }
            */
            break;
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

    conn = http_ssl_conn_creat("apis.t2.5itianyuan.com");
    if (!conn) {
        return -1;
    }

    const char *post_data = "gatewaySn=201703091158&macAddress=20-17-03-09-11-58&vendorId=HUADI&productId=GZ6200&hardwareVersion=20160608&softwareVersion=20160608&moduleList=%5B%7B%22moduleSn%22%3A%22MODULE-ZIGBEE-0001%22%2C%22vendorCode%22%3A%22HUADI%22%2C%22productCode%22%3A%22M1-001%22%2C%22moduleType%22%3A%22zigbee%22%2C%22macAddress%22%3A%2211-22-33-44-55-66%22%7D%5D\r\n\r\n";

    snprintf(conn->http_data, sizeof(conn->http_data), g_http_post_header_fmt, 
            "/smarthome-api/v1.1/gateway/signup",
            "POSTMAN",
            "apis.t2.5itianyuan.com",
            strlen(post_data), post_data);

    return 0;
}

struct timeval g_timeout;
static void http_timer_cb(int fd, short kind, void *userp)
{

    TYSCC_LOG(LOG_DEBUG, "------------------");

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
