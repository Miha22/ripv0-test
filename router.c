#define EVENT_LOG_DEBUG 0
#define EVENT_LOG_MSG   1
#define EVENT_LOG_WARN  2
#define EVENT_LOG_ERR   3

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <event2/event.h>
#include <event2/event_struct.h>
#include "patricia.h"

#define MAXBUFLEN 100
#define MAX_ENTRIES 25
#define CHECK_INTERVAL 3

typedef void (*event_callback_fn)(evutil_socket_t, short, void *);

uint8_t socket_write_ready = 0;
bool table_updated = false;
uint16_t table_version = 0;

//20 bytes
struct rip_entry {
    uint16_t family;         // Address Family Identifier (e.g., 2 for IP)
    uint16_t route_tag;      // Route Tag (typically 0)
    uint32_t ip_addr;        // IP address of the destination network
    uint32_t subnet_mask;    // Subnet mask for the network
    uint32_t next_hop;       // IP address of the next hop router
    uint32_t metric;         // Metric (1 to 16)
};

//4 bytes + 20 * n
struct rip_packet {
	uint8_t cmd;
	uint8_t ver;
	uint16_t pad;
    uint8_t num_entries;
	struct rip_entry entries[MAX_ENTRIES];
};

const char* destinations[3] = { "4950", "4951", "4952" };
char* self_port = NULL;

void encode_packet(struct rip_packet *p, char *buffer, size_t *out_len) {
	char *ptr = buffer;
	*ptr++ = p->cmd;
	*ptr++ = p->ver;
	uint16_t pad = htons(p->pad);
	memcpy(ptr, &pad, sizeof (uint16_t));
	ptr += sizeof(uint16_t);
    *ptr++ = p->num_entries;

	for (uint8_t i = 0; i < *ptr; i++)
	{
		struct rip_entry e = p->entries[i];
		uint16_t family = htons(e.family);
		uint16_t route_tag = htons(e.route_tag);      // Route Tag (typically 0)
		uint32_t ip_addr = htonl(e.ip_addr);        // IP address of the destination network
		uint32_t subnet_mask = htonl(e.subnet_mask);    // Subnet mask for the network
		uint32_t next_hop = htonl(e.next_hop);       // IP address of the next hop router
		uint32_t metric = htonl(e.metric);         // Metric (1 to 16)

		memcpy(ptr, &family, sizeof (uint16_t));
		ptr += sizeof(uint16_t);
		memcpy(ptr, &route_tag, sizeof (uint16_t));
		ptr += sizeof(uint16_t);
		memcpy(ptr, &ip_addr, sizeof (uint32_t));
		ptr += sizeof(uint32_t);
		memcpy(ptr, &subnet_mask, sizeof (uint32_t));
		ptr += sizeof(uint32_t);
		memcpy(ptr, &next_hop, sizeof (uint32_t));
		ptr += sizeof(uint32_t);
		memcpy(ptr, &metric, sizeof (uint32_t));
		ptr += sizeof(uint32_t);
	}

	*out_len = ptr - buffer;
} 

void decode_packet(struct rip_packet *packet, char *buffer) {
	char *ptr = buffer;

    // Read command and version
    packet->cmd = *ptr++;
    packet->ver = *ptr++;

    // Read and convert the unused field
    uint16_t pad;
    memcpy(&pad, ptr, sizeof(uint16_t));
    packet->pad = ntohs(pad);
    ptr += sizeof(uint16_t);
    packet->num_entries = *ptr++;

    // Decode each entry in the packet
    for (int i = 0; i < packet->num_entries; i++) {
        struct rip_entry *entry = &packet->entries[i];

        uint16_t family, route_tag;
        uint32_t ip_addr, subnet_mask, next_hop, metric;

        // Copy each field and convert from network byte order
        memcpy(&family, ptr, sizeof(uint16_t));
        entry->family = ntohs(family);
        ptr += sizeof(uint16_t);

        memcpy(&route_tag, ptr, sizeof(uint16_t));
        entry->route_tag = ntohs(route_tag);
        ptr += sizeof(uint16_t);

        memcpy(&ip_addr, ptr, sizeof(uint32_t));
        entry->ip_addr = ntohl(ip_addr);
        ptr += sizeof(uint32_t);

        memcpy(&subnet_mask, ptr, sizeof(uint32_t));
        entry->subnet_mask = ntohl(subnet_mask);
        ptr += sizeof(uint32_t);

        memcpy(&next_hop, ptr, sizeof(uint32_t));
        entry->next_hop = ntohl(next_hop);
        ptr += sizeof(uint32_t);

        memcpy(&metric, ptr, sizeof(uint32_t));
        entry->metric = ntohl(metric);
        ptr += sizeof(uint32_t);
    }
}

void receive_update(int sockfd) {
    char buffer[512];
    struct sockaddr_in src_addr;
    socklen_t addr_len = sizeof(src_addr);

    int len = recvfrom(sockfd, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&src_addr, &addr_len);
    if (len > 0) {
        buffer[len] = '\0';
        printf("Received update from %s: %s\n", inet_ntoa(src_addr.sin_addr), buffer);
        // Process received RIP update here
    } else {
        perror("recvfrom failed");
    }
}

void read_callback(evutil_socket_t sockfd, short events, void *arg) {
    char buffer[512];
    struct sockaddr_in src_addr;
    socklen_t addrlen = sizeof(src_addr);

    int len = recvfrom(sockfd, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&src_addr, &addrlen);
    if (len > 0) {
        buffer[len] = '\0';
        struct rip_packet packet;
        decode_packet(&packet, buffer);

        printf("Received from %d:%s: cmd=%u, ver=%u, num_entries=%u\n", src_addr.sin_port,
               inet_ntoa(src_addr.sin_addr), packet.cmd, packet.ver, packet.num_entries);

        for (int i = 0; i < packet.num_entries; i++) {
            printf("Entry %d: Family=%u, Metric=%u\n",
                   i, packet.entries[i].family, packet.entries[i].metric);
        }

        // Update table status
        table_updated = true;
        table_version++;
    } else {
        perror("recvfrom error");
    }
}

struct rip_packet* get_mock_packet() {
	struct rip_entry e = { .family = 1123, .route_tag = 1234, .ip_addr = 1345, .subnet_mask = 1456, .next_hop = 1567, .metric = 1678 };
	struct rip_entry e1 = { .family = 2123, .route_tag = 2234, .ip_addr = 2345, .subnet_mask = 2456, .next_hop = 2567, .metric = 2678 };
	//struct rip_packet p = { .cmd = 255, .ver = 2, .entries = { e, e1 }};
	struct rip_packet *ptr = (struct rip_packet *)malloc(sizeof (struct rip_packet));
	ptr->cmd = 255;
	ptr->ver = 2;
    ptr->num_entries = 2;
	ptr->entries[0] = e;
	ptr->entries[1] = e1;
	// char *buffer = (char *)malloc(sizeof (struct rip_packet));
	// size_t len = 0;
	// encode_packet(&p, buffer, &len);
	return ptr;
}

int send_packet(int sockfd, const char *ip, const char *port, const char *message, size_t msg_len) {
    struct addrinfo hints, *servinfo, *p;
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;       // IPv4
    hints.ai_socktype = SOCK_DGRAM; // UDP

    if ((rv = getaddrinfo(ip, port, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }

    for (p = servinfo; p != NULL; p = p->ai_next) {
        if (sendto(sockfd, message, msg_len, 0, p->ai_addr, p->ai_addrlen) == -1) {
            perror("sendto");
            continue;
        }
        printf("Sent %zu bytes to %s:%s\n", msg_len, port, ip);
        break; // Successfully sent
    }

    freeaddrinfo(servinfo);
    return 0;
}

void write_callback(evutil_socket_t fd, short events, void *arg) {
    struct rip_packet *packet = (struct rip_packet *)get_mock_packet();
    char buf[512];
    size_t len = 0;

    encode_packet(packet, buf, &len);

    const char *other_ports[2];
    int index = 0;

    for (uint8_t i = 0; i < 3; i++) {
        if (strcmp(destinations[i], self_port) != 0) {
            other_ports[index++] = destinations[i];
        }
    }

    for (uint8_t i = 0; i < 2; i++) {
        send_packet(fd, "127.0.0.1", other_ports[i], buf, len);
    }

    free(packet);
}

void *get_in_addr(struct sockaddr *saddr) {
	if (saddr->sa_family == AF_INET) {
		return &(((struct sockaddr_in *)saddr)->sin_addr);
	}
	return &(((struct sockaddr_in6 *)saddr)->sin6_addr);
}

int get_socket(uint16_t family, uint16_t flags, char* ip, char* port) {
    int fd, yes = 1, rv;
    struct addrinfo hints, *ai, *p;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = family;
    hints.ai_socktype = SOCK_DGRAM;  // UDP socket
    hints.ai_flags = flags;

    // Get address information
    if ((rv = getaddrinfo(ip, port, &hints, &ai)) != 0) {
        fprintf(stderr, "Error getting addrinfo: %s\n", gai_strerror(rv));
        exit(EXIT_FAILURE);
    }

    // Iterate through possible addresses and bind
    for (p = ai; p != NULL; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) {
            perror("socket");
            continue;
        }

        // Allow reuse of the port
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
            perror("setsockopt");
            close(fd);
            continue;
        }

        // Bind the socket to the port
        if (bind(fd, p->ai_addr, p->ai_addrlen) < 0) {
            perror("bind");
            close(fd);
            continue;
        }

        break; // Successfully bound
    }

    if (p == NULL) {
        fprintf(stderr, "listener: failed to bind socket\n");
        freeaddrinfo(ai);
        return -1;
    }

    freeaddrinfo(ai);
    return fd;
}


int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        return 1;
    }

    self_port = argv[1];
    struct event_base *ebase = event_base_new();
    if (!ebase) {
        fprintf(stderr, "Failed to create event base\n");
        return 1;
    }

    // Create socket
    int sockfd = get_socket(AF_INET, AI_PASSIVE, NULL, self_port);
    if (sockfd == -1) {
        fprintf(stderr, "Failed to create socket\n");
        return 1;
    }

    // Create read event
    struct event *read_event = event_new(ebase, sockfd, EV_READ | EV_PERSIST, read_callback, NULL);
    if (!read_event || event_add(read_event, NULL) == -1) {
        fprintf(stderr, "Failed to set up read event\n");
        return 1;
    }

    // Create periodic write event
    srand(time(NULL));
    struct timeval timer_interval = {3 + (rand() % 2 + 1), 0};
    struct event *periodic_event = event_new(ebase, sockfd, EV_PERSIST, write_callback, NULL);
    if (!periodic_event || event_add(periodic_event, &timer_interval) == -1) {
        fprintf(stderr, "Failed to set up periodic write event\n");
        return 1;
    }

    printf("Listening for packets on port %s...\n", self_port);
    event_base_dispatch(ebase);

    // Cleanup
    event_free(read_event);
    event_free(periodic_event);
    close(sockfd);
    event_base_free(ebase);

    return 0;
}