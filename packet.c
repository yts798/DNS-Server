/* Packet Module for DNS server */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "packet.h"

// This function parse the packet header
int parse_header(unsigned char *packet, int len, int curr, DNS_Header *header) { 
    unsigned char ch;

    // parse packet id
    header->id = (unsigned short) HEX2_to_INT(packet[curr], packet[curr+1]);

    curr += TWO_BYTE;
    
    // parse qr, opcode, aa, tc, rd, ra, z, rcode
    ch = packet[curr];

    // convert to binary string
    int bin_1[BINARY_LEN];
    for(int i = 0; i < BINARY_LEN; i++) bin_1[(BINARY_LEN - 1)-i] = (ch >> i) & 1;

    curr += ONE_BYTE;
    ch = packet[curr];
    
    // convert to binary string
    int bin_2[BINARY_LEN];
    for(int i = 0; i < 8; i++) bin_2[7-i] = (ch >> i) & 1;

    header->qr = bin_1[0];

    header->opcode = BIN4_to_INT(bin_1[1], bin_1[2], bin_1[3], bin_1[4]);
    header->aa = bin_1[5];
    header->tc = bin_1[6];
    header->rd = bin_1[7];
    header->ra = bin_2[0];

    header->z = BIN3_to_INT(bin_2[1], bin_2[2], bin_2[3]);
    header->rcode = BIN4_to_INT(bin_2[4], +bin_2[5], bin_2[6], bin_2[7]);

    curr += ONE_BYTE;
    // parse 4 counts
    header->qdcount = HEX2_to_INT(packet[curr], packet[curr+1]);
    curr+= TWO_BYTE;
    header->ancount = HEX2_to_INT(packet[curr], packet[curr+1]);
    curr+= TWO_BYTE;
    header->nscount = HEX2_to_INT(packet[curr], packet[curr+1]);
    curr+= TWO_BYTE;
    header->arcount = HEX2_to_INT(packet[curr], packet[curr+1]);
    curr+= TWO_BYTE;

    return curr;
}

// This function parse the packet question
int parse_question(unsigned char *packet, int len, int curr, DNS_Question *question) {
    int end_name = curr;
    // search the end of domain name
    while (packet[end_name]!= 0) {
        end_name++;
    }
    int seek_len = 0;
    int curr_len;
    int name_index = 0;
    int add_dot = 0;

    // allocate space for domain name
    question->qname = (unsigned char *)malloc((end_name - curr)*sizeof(unsigned char));

    // save domain name
    while (curr < end_name) {
        // extract len for next phrase
        if (!seek_len) {
            curr_len = packet[curr];
            seek_len = curr_len;
            if (add_dot) {
                question->qname[name_index++] = DOT;
                add_dot = 0;
            }
        }
        // save next phrase
        else {
            question->qname[name_index++] = packet[curr];
            add_dot = 1;
            seek_len -= 1;
        }
        curr+=ONE_BYTE;
    }
    question->qname[name_index] = '\0';

    curr += ONE_BYTE;


    question->qtype = HEX2_to_INT(packet[curr], packet[curr+1]);
    curr+=TWO_BYTE;

    question->qclass = HEX2_to_INT(packet[curr], packet[curr+1]);
    curr+=TWO_BYTE;
    return curr;
}

// This function parse the packet answer
int parse_answer(unsigned char *packet, int len, int curr, DNS_Answer *answer) {
    // parse name, type, class, ttl,
    answer->name = HEX2_to_INT(packet[curr], packet[curr+1]);
    curr+=TWO_BYTE;


    answer->type = HEX2_to_INT(packet[curr], packet[curr+1]);
    curr+=TWO_BYTE;

    answer->class =  HEX2_to_INT(packet[curr], packet[curr+1]);
    curr+=TWO_BYTE;

    answer->ttl =  HEX4_to_INT(packet[curr], packet[curr+1], packet[curr+2], packet[curr+3]);
    curr += FOUR_BYTE;

    // parse response data length
    answer->rdlength = HEX2_to_INT(packet[curr], packet[curr+1]);
    curr+=TWO_BYTE;

    answer->rdata = (unsigned char *)malloc((answer->rdlength + 1)*sizeof(unsigned char));

    // parse response data
    for (int i = 0; i < answer->rdlength; i++) {
        answer->rdata[i] = packet[curr++];
    }
    answer->rdata[answer->rdlength] = '\0';
    return 0;
}

// This function convers 2 bytes of hexadecimal to decimal integer
int HEX2_to_INT(unsigned char h1, unsigned char h2) {
    return (int) (h1*HEX*HEX + h2);
}

// This function convers 4 bytes of hexadecimal to decimal integer
int HEX4_to_INT(unsigned char h1, unsigned char h2, unsigned char h3, unsigned char h4) {
    return (int) (h1*HEX*HEX*HEX*HEX*HEX*HEX + h2*HEX*HEX*HEX*HEX + h3*HEX*HEX + h4);
}

// This function convers 3 bits of binary to decimal integer
int BIN3_to_INT(unsigned char h1, unsigned char h2, unsigned char h3) {
    return (int) (h1*BIN*BIN + h2*BIN+ h3);
}

// This function convers 4 bits of binary to decimal integer
int BIN4_to_INT(unsigned char h1, unsigned char h2, unsigned char h3, unsigned char h4) {
    return (int) (h1*BIN*BIN*BIN + h2*BIN*BIN + h3*BIN + h4);
}

    




