/*  Utilities Module for DNS server */

#ifndef utils_H
#define utils_H

#define Fail_msg "unimplemented request"
#define REQUEST "requested"
#define LOCATE "is at"
#define PORT "8053"
#define HEX 16
#define AAAA_TYPE 28
#define DEFAULT_BACKLOG 10
#define HAS_INCOMING 1
#define QR_MODIFY 4
#define RCODE_MODIFY 5
#define RA_MODIFY 5
#define TIMESTAMP_LEN 25
#define HEADER0 0
#define HEADER1 1
#define OFFSET2 2


// create timestamp to file
time_t create_timestamp(FILE *fp);

// intialise server
int server();

// initialise client
int client(char *ip_addr, char *port_num);

// form a new packet for sending
void form_packet(unsigned char *new_msg, unsigned char *old_header, unsigned char *old_packet, int old_len);

#endif
