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

#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define TYSCC_LOG(p, fmt, ...) \
    printf("[%s][%d]" fmt "\n", __func__, __LINE__, ##__VA_ARGS__)

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
        perror ("Connect");
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

int main(void)
{
    http_ssl_global_init();

    http_tcp_connect("apis.t2.5itianyuan.com", 443);

    http_ssl_global_fini();

    return 0;
}
