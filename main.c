#include<stdio.h> 
#include<string.h>    
#include<stdlib.h>    
#include<sys/socket.h>    
#include<arpa/inet.h> 
#include<netinet/in.h>
#include<unistd.h>    
#include<netdb.h>
#include<time.h>

#include "packet.h"
#include "utils.h"

// The main function for dns server functionality
void DNS(char *ip_addr, char *port_num);

// main function for project 2!
int main(int argc, char* argv[]) {
	// check command-line argument integrity
	if (argc < 3) {
		fprintf(stderr, "No enough command-line arguments provided\n");
		exit(EXIT_FAILURE);
	}
	
	// start the DNS SERVER!
	DNS(argv[1], argv[2]);
	
    return 0;
}

// This function control the main process of my DNS server
void DNS(char *ip_addr, char *port_num) {
	int sockfd, newsockfd, index = 0, sockfd_clnt = 0;
	struct sockaddr_storage client_addr;
	socklen_t client_addr_size;
	// create log file
	FILE *out = fopen("dns_svr.log", "a");

	// save dns query and response
	DNS_Header *header = NULL;
    header = (DNS_Header *)malloc(sizeof(header));
    DNS_Question *question = NULL;
    question = (DNS_Question *)malloc(sizeof(question));
    DNS_Answer *answer = NULL;
    answer = (DNS_Answer *)malloc(sizeof(answer));
	DNS_Header *header_res = NULL;
	header_res = (DNS_Header *)malloc(sizeof(header_res));    
	DNS_Question *question_res = NULL;
	question_res = (DNS_Question *)malloc(sizeof(question_res));
	DNS_Answer *answer_res = NULL;
	answer_res = (DNS_Answer *)malloc(sizeof(answer_res));

	// save dns query and response length
	unsigned char pkt_header[OFFSET2];
	unsigned char res_header[OFFSET2];

	// save packet msg
	int pkt_len = 0, new_len = 0, res_len = 0;
	unsigned char *pkt_msg = NULL;
	unsigned char *fail_back = NULL;
	unsigned char *pkt_res = NULL;
	unsigned char *new_msg = NULL;
	unsigned char *msgback = NULL;

	// receive socket id for server
    sockfd = server();

	// try to accept
	client_addr_size = sizeof client_addr;

	// for readind TCP Stream
	unsigned char byte_buf[ONE_BYTE];
	int read_count = 0;
	
	// for saving domain name
	char ip[INET6_ADDRSTRLEN];

	// keep receiving query
	while (HAS_INCOMING) {
		read_count = 0;
		// accept query
		newsockfd = accept(sockfd, (struct sockaddr*)&client_addr, &client_addr_size);
		if (newsockfd < 0) {
			perror("accept");
			exit(EXIT_FAILURE);
		}
	
		// read the packet continuously
		read(newsockfd, byte_buf, ONE_BYTE);
		pkt_header[HEADER0] = byte_buf[0];
		read(newsockfd, byte_buf, ONE_BYTE);
		pkt_header[HEADER1] = byte_buf[0];
		pkt_len = HEX2_to_INT(pkt_header[HEADER0], pkt_header[HEADER1]);
		pkt_msg = (unsigned char *)malloc(pkt_len*sizeof(unsigned char));

		while (read_count < pkt_len) {
			read(newsockfd, byte_buf, ONE_BYTE);
			pkt_msg[read_count++] = byte_buf[0];
		}

		// parse packet header & question
		index = parse_header(pkt_msg, pkt_len, index, header);
    	index = parse_question(pkt_msg, pkt_len, index, question);

		// log activity 
		create_timestamp(out);
    	fprintf(out, "%s %s\n", REQUEST, question->qname);

		// determine whether its a AAAA type
		if (question->qtype != AAAA_TYPE) {
			// log unimplementead request
			create_timestamp(out);
			fprintf(out, "%s\n", Fail_msg);
			
			// send packet back to original client
			fail_back =  (unsigned char *)malloc((pkt_len+2)*sizeof(unsigned char));
			form_packet(fail_back, pkt_header, pkt_msg, pkt_len);

        	header->rcode = ERROR_R_CODE;

			// change query to response
			fail_back[QR_MODIFY] = fail_back[QR_MODIFY] | QR_RES;
			// change Rcode to 4
			fail_back[RCODE_MODIFY] = fail_back[RCODE_MODIFY] | ERROR_R_CODE;
			// Set recursion desirable
			fail_back[RA_MODIFY] = fail_back[RCODE_MODIFY] | RA;

			write(newsockfd, fail_back, pkt_len + OFFSET2);
			index = 0;
    	}

		else {
			// form new dns packet
			new_len = pkt_len + OFFSET2;
			new_msg =  (unsigned char *)malloc((new_len)*sizeof(unsigned char));

			form_packet(new_msg, pkt_header, pkt_msg, pkt_len);

			// connect to clinet
			sockfd_clnt = client(ip_addr, port_num);
			
			// write to clinet
			write(sockfd_clnt, new_msg, new_len);
			
			read(sockfd_clnt, res_header, OFFSET2);
			// receive response packet
			res_len = HEX2_to_INT(res_header[HEADER0], res_header[HEADER1]);
			pkt_res = (unsigned char *)malloc(res_len*sizeof(unsigned char));
			read(sockfd_clnt, pkt_res, res_len);

			// parse response packet
			index = 0;
			index = parse_header(pkt_res, res_len, index, header_res);
			index = parse_question(pkt_res, res_len, index, question_res);
			index = parse_answer(pkt_res, res_len, index, answer_res);

			// convert to IPV6 address and log it for AAAA type response
 	   		inet_ntop(AF_INET6, answer_res->rdata, ip, sizeof(ip));
			if (answer_res->type == AAAA_TYPE) {		
				create_timestamp(out);
    			fprintf(out, "%s %s %s\n", question->qname, LOCATE, ip);
			}
	
	
			msgback =  (unsigned char *)malloc((res_len+OFFSET2)*sizeof(unsigned char));
			form_packet(msgback, res_header, pkt_res, res_len);

			// Set recursion desirable
			msgback[RA_MODIFY] = msgback[RA_MODIFY] | RA;
		
			write(newsockfd, msgback, res_len+OFFSET2);
		}
		// flush the buffer
		fflush(out);
		fflush(stdout);
		}

	// close the log file and all socket
	fclose(out);
	close(sockfd);
	close(newsockfd);
	close(sockfd_clnt);
}

