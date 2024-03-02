#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h> 
#include <sys/socket.h>   
#include <netinet/in.h>  
#include <time.h>

#define QUERY "query"
#define RESPONSE "response"
#define HEX 16
#define AAAA_TYPE 7168
#define Fail_msg "unimplemented request"
#define REQUEST "requested"
#define LOCATE "is at"


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

typedef struct DNS_Question {
    unsigned char *qname;
    unsigned short qtype;
    unsigned short qclass;

} DNS_Question;

typedef struct {
    unsigned short name;
    unsigned short type;
    unsigned short class;
    unsigned int ttl;
    unsigned short rdlength;
    unsigned char *rdata;
} DNS_Answer;

// get packet length
int read_header();
// load packet data
void read_msg(unsigned char *packet, int len);

// parse packet header
int parse_header(unsigned char *packet, int len, int curr, DNS_Header *header);
int parse_question(unsigned char *packet, int len, int curr, DNS_Question *question);
int parse_answer(unsigned char *packet, int len, int curr, DNS_Answer *answer);

// void parse_answer

int main(int argc, char* argv[]) {
    // FILE *packet_file;
    int is_res = 0;
    int valid_type = 1;
    int index = 0;
    unsigned int packet_len;
    unsigned char *packet = NULL;
    DNS_Header *header = NULL;
    header = (DNS_Header *)malloc(sizeof(header));
    DNS_Question *question = NULL;
    question = (DNS_Question *)malloc(sizeof(question));
    DNS_Answer *answer = NULL;
    answer = (DNS_Answer *)malloc(sizeof(answer));

    // produce log file
    FILE *out = fopen("dns_svr.log", "a");

    // parse first CML argument
    if (!strcmp(argv[1], RESPONSE)) is_res = 1;
    // get packet length
    packet_len = read_header();

    // load packet data
    packet = (unsigned char *)malloc(packet_len*sizeof(unsigned char));
    read_msg(packet, packet_len);

    time_t curr;
    struct tm *local_time;
    char curr_time[25];
    time(&curr);
    local_time = localtime(&curr);
    strftime(curr_time, sizeof(curr_time), "%FT%T%z", local_time);

    index = parse_header(packet, packet_len, index, header);
    index = parse_question(packet, packet_len, index, question);


    if (question->qtype != AAAA_TYPE) {
        fprintf(out, "%s %s %s\n", curr_time, REQUEST, question->qname);
        fprintf(out, "%s %s\n", curr_time, Fail_msg);
        
        header->rcode = 4;
        return 0 ;
    }

    if (!is_res) {
        fprintf(out, "%s %s %s\n", curr_time, REQUEST, question->qname);
    }
    if (valid_type && is_res) {
        if  (ntohs(header->ancount)) {
        index = parse_answer(packet, packet_len, index, answer);
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, answer->rdata, ip, sizeof(ip));
        fprintf(out, "%s %s %s %s\n", curr_time, question->qname, LOCATE, ip);
        }
    }
    return 0;


}

// get packet length
int read_header() {
    unsigned char h1, h2;
    
    h1 = (unsigned char) getchar();
    h2 = (unsigned char) getchar();
    return (int) (h1*HEX*HEX + h2);
}
  
// load packet data
void read_msg(unsigned char *packet, int len) {
    for (int i = 0; i < len; i++) {
        packet[i] = (unsigned char) getchar();
    }

}

int parse_header(unsigned char *packet, int len, int curr, DNS_Header *header) {
    unsigned char ch;
    header->id = (unsigned short) htons(packet[0]*HEX*HEX + packet[1]);

    ch = packet[2];
    int bin_1[8];
    int bin_2[8];
    for(int i = 0; i < 8; i++) bin_1[7-i] = (ch >> i) & 1;

    ch = packet[3];
    
    for(int i = 0; i < 8; i++) bin_2[7-i] = (ch >> i) & 1;

    header->qr = bin_1[0];

    header->opcode = bin_1[1]*2*2*2+bin_1[2]*2*2+bin_1[3]*2+bin_1[4];

    header->aa = bin_1[5];
    header->tc = bin_1[6];
    header->rd = bin_1[7];
    header->ra = bin_2[0];

    header->z = bin_2[1]*2*2+bin_2[2]*2+bin_2[3];
    header->rcode = bin_2[4]*2*2*2+bin_2[5]*2*2+bin_1[3]*2+bin_1[4];

    header->qdcount = ntohs((packet[4]*HEX*HEX + packet[5]));
    header->ancount = ntohs((packet[6]*HEX*HEX + packet[7]));
    header->nscount = ntohs((packet[8]*HEX*HEX + packet[9]));
    header->arcount = ntohs((packet[10]*HEX*HEX + packet[11]));

    return 12;
}


int parse_question(unsigned char *packet, int len, int curr, DNS_Question *question) {
    int end_name = curr;
    while (packet[end_name]!= 0) {
        end_name++;
    }
    int seek_len = 0;
    int curr_len;
    int name_index = 0;
    int add_dot = 0;

    question->qname = (unsigned char *)malloc((end_name - curr)*sizeof(unsigned char));
    while (curr < end_name) {
        if (!seek_len) {
            curr_len = packet[curr];
            seek_len = curr_len;
            if (add_dot) {
                question->qname[name_index++] = '.';
                add_dot = 0;
            }
        }
        else {
            question->qname[name_index++] = packet[curr];
            add_dot = 1;
            seek_len -= 1;
        }


        curr+=1;
    }


    question->qname[name_index] = '\0';
    curr += 1;

    question->qtype = htons(packet[curr]*HEX*HEX + packet[curr+1]);
    curr+=2;

    question->qclass = htons(packet[curr]*HEX*HEX + packet[curr+1]);
    curr+=2;


    

    return curr;
}
int parse_answer(unsigned char *packet, int len, int curr, DNS_Answer *answer) {

    
    answer->name = htons(packet[curr]*HEX*HEX + packet[curr+1]);
    curr+=2;


    answer->type = htons(packet[curr]*HEX*HEX + packet[curr+1]);
    curr+=2;


    answer->name = htons(packet[curr]*HEX*HEX + packet[curr+1]);
    curr+=2;

    answer->ttl = (packet[curr]*HEX*HEX*HEX + packet[curr+1]*HEX*HEX + 
    packet[curr+2]*HEX + packet[curr+3]);
    curr += 4;
    answer->rdlength = packet[curr]*HEX*HEX + packet[curr+1];

    curr+=2;

    answer->rdata = (unsigned char *)malloc((answer->rdlength + 1)*sizeof(unsigned char));

    for (int i = 0; i < answer->rdlength; i++) {
        answer->rdata[i] = packet[curr++];
    }
    answer->rdata[answer->rdlength] = '\0';


    return 0;
}





