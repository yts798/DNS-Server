/* Packet Module for DNS server */
#ifndef packet_H
#define packet_H

#define QUERY "query"
#define RESPONSE "response"
#define DOT '.'
#define HEX 16
#define BIN 2
#define AAAA_TYPE 28
#define ONE_BYTE 1
#define TWO_BYTE 2
#define FOUR_BYTE 4
#define BINARY_LEN 8
#define ERROR_R_CODE 4
#define QR_RES 128
#define RA 128

// Structure for packet Header
typedef struct {
    unsigned short id;
    unsigned char qr :1;
    unsigned char opcode :4;
    unsigned char aa: 1;
    unsigned char tc: 1;
    unsigned char rd: 1;
    unsigned char ra: 1;
    unsigned char z: 3;
    unsigned char rcode: 4;
    
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
} DNS_Header;

// Structure for packet Question
typedef struct DNS_Question {
    unsigned char *qname;
    unsigned short qtype;
    unsigned short qclass;

} DNS_Question;

// Structure for packet Answer
typedef struct {
    unsigned short name;
    unsigned short type;
    unsigned short class;
    unsigned int ttl;
    unsigned short rdlength;
    unsigned char *rdata;
} DNS_Answer;

// This function parse the packet header
int parse_header(unsigned char *packet, int len, int curr, DNS_Header *header);

// This function parse the packet question
int parse_question(unsigned char *packet, int len, int curr, DNS_Question *question);

// This function parse the packet answer
int parse_answer(unsigned char *packet, int len, int curr, DNS_Answer *answer);

// This function convers 2 bytes of hexadecimal to decimal integer
int HEX2_to_INT(unsigned char h1, unsigned char h2);

// This function convers 4 bytes of hexadecimal to decimal integer
int HEX4_to_INT(unsigned char h1, unsigned char h2, unsigned char h3, unsigned char h4);

// This function convers 3 bits of binary to decimal integer
int BIN3_to_INT(unsigned char h1, unsigned char h2, unsigned char h3);

// This function convers 4 bits of binary to decimal integer
int BIN4_to_INT(unsigned char h1, unsigned char h2, unsigned char h3, unsigned char h4);

#endif
