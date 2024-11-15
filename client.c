#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>

#define SERVERPORT "4950"
#define SERVERIP "192.168.0.3"

int main(int argc, char* argv[]) {

    if(argc != 3) {
        fprintf(stderr,"usage: %s hostname message\n", argv[0]);
        exit(1);
    }

    int sockfd, rv, numbytes;
    struct addrinfo hints, *servinfo, *p;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    if((rv = getaddrinfo(argv[1], SERVERPORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }

    for(p = servinfo; p != NULL; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if(sockfd < 0) {
			fprintf(stderr, "listener: socket\n");
            continue;
        }

        break;
    }

    if(p == NULL) {
        fprintf(stderr, "failed to create socket: %s\n", gai_strerror(rv));
        freeaddrinfo(servinfo);
        exit(1);
    }

    if ((numbytes = sendto(sockfd, argv[2], strlen(argv[2]), 0, p->ai_addr, p->ai_addrlen)) == -1) { 
        fprintf(stderr, "listener: socket\n");
        freeaddrinfo(servinfo);
        exit(1);
    }

    freeaddrinfo(servinfo);

    return 0;
}