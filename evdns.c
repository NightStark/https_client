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

#include <event2/event.h>
#include <event2/util.h>
#include <event2/dns.h>

struct event_base * g_evbase = 0;
struct evdns_base * g_dnsbase = 0;

static void _dns_callback(int errcode, struct evutil_addrinfo *addr, void *ptr)
{
    if (errcode) {
        printf("%s -> %s\n", (char*)ptr, evutil_gai_strerror(errcode));
    } else {
        struct evutil_addrinfo *ai;
        char ip[128];
        printf("dns resolved,hostname - %s, ip :\n", (char*)ptr);
        for (ai = addr; ai; ai = ai->ai_next) {
            const char *s = NULL;
            if (ai->ai_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in *)ai->ai_addr;
                s = evutil_inet_ntop(AF_INET, &sin->sin_addr, ip, 128);
            } else if (ai->ai_family == AF_INET6) {
                struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ai->ai_addr;
                s = evutil_inet_ntop(AF_INET6, &sin6->sin6_addr, ip, 128);
            }
            if(s) {
                printf("  %s\n", s);
            }
        }
    }

    if(addr)evutil_freeaddrinfo(addr);
}


struct evdns_base * setup_evdns_base(struct event_base *base)
{
    if(g_dnsbase) {
        return g_dnsbase;
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

        g_dnsbase = dnsbase;
        return dnsbase;
    }
}


static int lookup_host(const char * host)
{
    struct evutil_addrinfo hints;
    struct evdns_getaddrinfo_request *req;
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

    req = evdns_getaddrinfo(g_dnsbase, host, NULL ,
            &hints, _dns_callback, (void*)host);
    if (req == NULL)
    {
        printf("    [request for %s returned immediately]\n", host);
        return -1;
    }
    return 0;
}



int main(int argc, char **argv)
{
#ifdef WIN32
    WORD wVersionRequested;
    WSADATA wsaData;

    wVersionRequested = MAKEWORD(2, 2);

    (void) WSAStartup(wVersionRequested, &wsaData);
#endif

    if(argc < 2)
    {
        printf("Usage: \n    dns_resolv hostname\n");
        return 0;
    }

    g_evbase = event_base_new();
    setup_evdns_base(g_evbase);
    if(lookup_host(argv[1]) == 0)
    {
        event_base_loop(g_evbase, 0);
    }

    event_base_free(g_evbase);
    evdns_base_free(g_dnsbase, 1);

#ifdef WIN32
    (void) WSACleanup();
#endif
    return 0;
}
