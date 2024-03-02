/* Utilities Module for DNS server */

#include<stdio.h> 
#include<string.h>    
#include<stdlib.h>    
#include<sys/socket.h>    
#include<arpa/inet.h> 
#include<netinet/in.h>
#include<unistd.h>    
#include<netdb.h>
#include<time.h>

#include "utils.h"

// create timestamp to file
time_t create_timestamp(FILE *fp) {
    time_t curr;
    struct tm *local_time;
    char curr_time[TIMESTAMP_LEN];
    time(&curr);
    local_time = localtime(&curr);
    strftime(curr_time, sizeof(curr_time), "%FT%T%z", local_time);
    fprintf(fp, "%s ", curr_time);
    return curr;
}

// form a new packet for sending
void form_packet(unsigned char *new_msg, unsigned char *old_header, unsigned char *old_packet, int old_len) {
    new_msg[HEADER0] = old_header[HEADER0];
	new_msg[HEADER1] = old_header[HEADER1];
    for (int i = 0; i < old_len; i++) {
		new_msg[i+OFFSET2] = old_packet[i];
	}
}



// intialise servser
// This function is adopted from week 9 practical code
int server() {
    int sockfd, s, re;
    struct addrinfo hints, *res;

    // initialise information
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;       
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;   

	// set initial port as "8053" and get address
    s = getaddrinfo(NULL, PORT, &hints, &res);
    if (s != 0) {
        fprintf(stderr, "getaddrinfo:%s\n", gai_strerror(s));
        exit(EXIT_FAILURE);
    }

    // Create socket
    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

    // Reuse port 
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &re, sizeof(int)) < 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    // Bind address to socket
    if (bind(sockfd, res->ai_addr, res->ai_addrlen) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }
    freeaddrinfo(res);

	// start listen with 10 backlog
    if (listen(sockfd, DEFAULT_BACKLOG) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    return sockfd;
}

// initialise client
// This function is adopted from week 9 practical code
int client(char *ip_addr, char *port_num) {
    int sockfd, addr_get;
	struct addrinfo hints, *servinfo, *rp;

	// Create address
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	// Get addrinfo of server
	addr_get= getaddrinfo(ip_addr, port_num, &hints, &servinfo);
	if (addr_get != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(addr_get));
		exit(EXIT_FAILURE);
	}

	// Connect to first valid result
	for (rp = servinfo; rp != NULL; rp = rp->ai_next) {
		sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sockfd == -1) {
			continue;
        }

		if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) != -1)
			break; // success

		close(sockfd);
	}
	if (rp == NULL) {
		fprintf(stderr, "client: failed to connect\n");
		exit(EXIT_FAILURE);
	}
	freeaddrinfo(servinfo);
    return sockfd;    
}





