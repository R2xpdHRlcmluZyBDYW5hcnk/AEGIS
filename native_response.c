/* IPv6 raw-IP responses for Snort's libdnet fallback. The engine is unchanged. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef void *(*open_fn)(void);
typedef void *(*close_fn)(void *);
typedef ssize_t (*send_fn)(void *, const void *, size_t);
static open_fn original_open;
static close_fn original_close;
static send_fn original_send;
static pthread_once_t symbols_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t handles_lock = PTHREAD_MUTEX_INITIALIZER;
struct handle { void *native; int ipv6; struct handle *next; };
static struct handle *handles;

static void symbols(void)
{
    original_open = (open_fn)dlsym(RTLD_NEXT, "ip_open");
    original_close = (close_fn)dlsym(RTLD_NEXT, "ip_close");
    original_send = (send_fn)dlsym(RTLD_NEXT, "ip_send");
}

void *ip_open(void)
{
    pthread_once(&symbols_once, symbols);
    if (!original_open || !original_close) { errno = ENOSYS; return NULL; }
    void *native = original_open();
    if (!native) return NULL;
    struct handle *entry = calloc(1, sizeof(*entry));
    if (!entry) { original_close(native); errno = ENOMEM; return NULL; }
    entry->native = native; entry->ipv6 = -1;
    pthread_mutex_lock(&handles_lock);
    entry->next = handles; handles = entry;
    pthread_mutex_unlock(&handles_lock);
    return native;
}

void *ip_close(void *native)
{
    pthread_once(&symbols_once, symbols);
    pthread_mutex_lock(&handles_lock);
    for (struct handle **p = &handles; *p; p = &(*p)->next) {
        if ((*p)->native != native) continue;
        struct handle *entry = *p; *p = entry->next;
        if (entry->ipv6 >= 0) close(entry->ipv6);
        free(entry); break;
    }
    pthread_mutex_unlock(&handles_lock);
    return original_close ? original_close(native) : NULL;
}

ssize_t ip_send(void *native, const void *buffer, size_t length)
{
    pthread_once(&symbols_once, symbols);
    if (!buffer || length < 1) { errno = EINVAL; return -1; }
    const uint8_t *packet = buffer;
    if ((packet[0] >> 4) != 6) {
        if (!original_send) { errno = ENOSYS; return -1; }
        return original_send(native, buffer, length);
    }
    if (length < 40 || length > 65575 ||
        (size_t)((packet[4] << 8) | packet[5]) + 40 != length) {
        errno = EINVAL; return -1;
    }
    pthread_mutex_lock(&handles_lock);
    struct handle *entry;
    for (entry = handles; entry && entry->native != native; entry = entry->next) {}
    if (!entry) { pthread_mutex_unlock(&handles_lock); errno = EBADF; return -1; }
    if (entry->ipv6 < 0) {
        entry->ipv6 = socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW);
        int enabled = 1;
        if (entry->ipv6 >= 0 && setsockopt(entry->ipv6, IPPROTO_IPV6, IPV6_HDRINCL, &enabled, sizeof(enabled)) < 0) {
            int error = errno; close(entry->ipv6); entry->ipv6 = -1; errno = error;
        }
    }
    ssize_t result = -1;
    if (entry->ipv6 >= 0) {
        struct sockaddr_in6 destination = { .sin6_family = AF_INET6 };
        memcpy(&destination.sin6_addr, packet + 24, 16);
        result = sendto(entry->ipv6, buffer, length, 0, (struct sockaddr *)&destination, sizeof(destination));
    }
    int error = errno;
    pthread_mutex_unlock(&handles_lock);
    errno = error;
    return result;
}
