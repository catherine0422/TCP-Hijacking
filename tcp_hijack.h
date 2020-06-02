
#ifndef TCP_HIJACK_H_
#define TCP_HIJACK_H_

#define BUF_SIZE 65536

int header_type;
#define LINKTYPE_NULL 0
#define LINKTYPE_ETH 1
#define LINKTYPE_WIFI 127

int fd; //the raw socket
void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);


#endif /* TCP_HIJACK_H_ */
 