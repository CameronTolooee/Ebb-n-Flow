/*
 * sniffer.cpp
 *
 *  Created on: Mar 7, 2014
 *      Author: ctolooee
 */
#include <iostream>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <signal.h>
#include "sniffer.h"

#define SIZE_ETHERNET 14
#define ETHER_TYPE_IP (0x0800)
#define ETHER_TYPE_8021Q (0x8100)

void *callback_on_packet;
void *callback_alarm;

Sniffer::Sniffer(int max, int time_between) : flow_table(max,time_between) {
	count = 0;
	handle = NULL;
	callback_alarm = (void *) this;
	callback_on_packet = (void *) this;
}

Sniffer::~Sniffer() {

}

void Sniffer::alarm_handler() {
	std::cout << "terminating sniffer.." << std::endl;
	pcap_breakloop(handle);
}

void Sniffer::alarm_handler_wrapper(int i) {
	/* Explicitly cast to a pointer to Sniffer */
	Sniffer* self = (Sniffer*) callback_alarm;
	(void)i; // Rid of that pesky warning
	/* Call function */
	self->alarm_handler();
}

void Sniffer::readFile(std::string filename, int offset, unsigned int time) {
	char errbuf[PCAP_ERRBUF_SIZE];
	handle = pcap_open_offline(filename.c_str(), errbuf);

	if (handle == NULL) {
		std::cerr << "Cannot open pcap file " << filename << ": " << errbuf
				<< std::endl;
		return;
	}
	sniff(handle, offset, time);
}

void Sniffer::readInterface(std::string interface, unsigned int time) {
	char errbuf[PCAP_ERRBUF_SIZE];
	handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, time * 1000, errbuf);
	if (handle == NULL) {
		std::cerr << "Cannot read device " << interface << ": " << errbuf
				<< std::endl;
		return;
	}
	sniff(handle, -1, time);
}

int Sniffer::sniff(pcap_t *handle, int offset, unsigned int time) {
	std::string filter = "tcp || udp || icmp"; //filter out everything except tcp icmp and udp
	bpf_u_int32 netmask = 0;
	struct bpf_program filter_loc; // location for compiled filter

	// ensure Ethernet headers are supported when reading from interface
	if (pcap_datalink(handle) != DLT_EN10MB) {
		std::cerr << "Device doesn't provide Ethernet headers - not supported"
				<< std::endl;
		return (5);
	}
	// compile filter
	if ((pcap_compile(handle, &filter_loc, filter.c_str(), 1, netmask)) == -1) {
		std::cerr << "Error parsing filter " << filter << ": "
				<< pcap_geterr(handle) << std::endl;
		return (2);
	}
	// apply filter
	if (pcap_setfilter(handle, &filter_loc) == -1) {
		std::cerr << "Error installing filter " << filter << ": "
				<< pcap_geterr(handle) << std::endl;
		return (2);
	}

	// alarm for stoping pcap loop after "time" seconds
	alarm(time);
	signal(SIGALRM, Sniffer::alarm_handler_wrapper);

	Info params = { time, offset, 0 };
	u_char* fake = (u_char*) &params;

	pcap_loop(handle, -1, Sniffer::on_packet_wrapper, fake);
	pcap_close(handle);
	return 0;
}

std::string Sniffer::getFlags(const struct tcphdr *tcp) {
	std::string result = "";
	if (tcp->fin)
		result += "FIN ";
	if (tcp->syn)
		result += "SYN ";
	if (tcp->ack)
		result += "ACK ";
	if (tcp->rst)
		result += "RST ";
	if (tcp->urg)
		result += "URG ";
	return result;
}

void Sniffer::on_packet(u_char *args, const struct pcap_pkthdr* header,
		const u_char* packet) {
	Info* params = (Info*) args; // params from the callback fxn
	unsigned int pkt_len = header->len;
	;
	unsigned long timestamp_sec = header->ts.tv_sec;
	unsigned long timestamp_usec = header->ts.tv_usec;
	const struct iphdr *ip;
	const struct tcphdr *tcp;
	const struct icmphdr *icmp;
	const struct udphdr *udp;
	u_int ip_hdr_len;
	u_int tcp_hdr_len;
	std::string protocol;
	int src_port = -1;
	int dst_port = -1;

	++count;

	// OFFSET FIRST decrement offset for each packet read
	if (params->offset > 0) {
		params->offset--;
		return;
	}
	// if first packet, init start time
	if (params->start == 0) {
		params->start = timestamp_sec;
	}
	// check if time is up
	if ((timestamp_sec - params->start) > params->time) {
		return;
	}
	ip = (struct iphdr*) (packet + SIZE_ETHERNET); // packet + size of eth header = ip header loc
	ip_hdr_len = ip->ihl * 4;
	// minimum ip header length = 20

	if (ip_hdr_len < 20) {
		std::cerr << "Failed to read IP header" << std::endl;
		return;
	}

	protocol = convertProtocol(ip->protocol);

	if (protocol == "ICMP") { //ICMP
		icmp = (struct icmphdr *) (packet + SIZE_ETHERNET + ip_hdr_len);
	} else if (protocol == "TCP") {	// TCP
		tcp = (struct tcphdr*) (packet + SIZE_ETHERNET + ip_hdr_len); // packet + eth header + ip header = tcp hdr loc
		src_port = ntohs(tcp->source);
		dst_port = ntohs(tcp->dest);
		tcp_hdr_len = tcp->doff * 4;
		// minimum tcp header length = 20
		if (tcp_hdr_len < 20) {
			std::cerr << "Failed to read TCP header\n" << std::endl;
		}
	} else if (protocol == "UDP") { // UDP
		udp = (struct udphdr*) (packet + SIZE_ETHERNET + ip_hdr_len); // packet + eth header + ip header = tcp hdr loc
		src_port = ntohs(udp->source);
		dst_port = ntohs(udp->dest);
	} else { // again, should never reach this due to filter
		std::cout << "Non TCP/UDP/ICMP protocol. Skipping.." << std::endl;
		return;
	}

	int af = ip->version; // get ip version number
	af = af == 4 ? AF_INET : AF_INET6;
	char ip_str_src[INET6_ADDRSTRLEN];
	char ip_str_dst[INET6_ADDRSTRLEN];

	if (inet_ntop(af, &ip->saddr, ip_str_src, INET6_ADDRSTRLEN) == NULL) {
		perror("inet_ntop");
	}
	if (inet_ntop(af, &ip->daddr, ip_str_dst, INET6_ADDRSTRLEN) == NULL) {
		perror("inet_ntop");
	}
	if(protocol == "TCP") {
		Packet pkt = { timestamp_sec, timestamp_usec, ip->protocol, ip_str_src,
				ip_str_dst, src_port, dst_port, getFlags(tcp), pkt_len, ntohl(tcp->ack_seq), ntohl(tcp->seq)};
		flow_table.update(&pkt);
	} else if (protocol == "ICMP") {
		char str[33];
		sprintf(str,"%d",icmp->code);
		std::string state(str);
		Packet pkt = { timestamp_sec, timestamp_usec, ip->protocol, ip_str_src,
				ip_str_dst, src_port, dst_port, state, pkt_len , 0 , 0};
		flow_table.update(&pkt);
	} else {
		Packet pkt = { timestamp_sec, timestamp_usec, ip->protocol, ip_str_src,
				ip_str_dst, src_port, dst_port, "", pkt_len, 0, 0 };
		flow_table.update(&pkt);
	}
	/*
	if (ip->protocol == 6) {
		std::cout << "           Flags: ";
		std::cout << getFlags(tcp) << std::endl;
		std::cout << "\n      Sequence #: " << ntohl(tcp->seq) << std::endl;
		std::cout << "Acknowledgment #: " << ntohl(tcp->ack_seq) << std::endl;
	} else if (ip->protocol == 1) {
		std::cout << "            Type: " << icmp->type << std::endl;
		std::cout << "        Sub-type: " << icmp->code << std::endl;
	}
	std::cout << "   Packet length: " << pkt_len << " Bytes\n" << std::endl;
	*/
}

void Sniffer::on_packet_wrapper(u_char *args, const struct pcap_pkthdr* header,
		const u_char* packet) {
	/* Explicitly cast to a pointer to Sniffer */
	Sniffer* self = (Sniffer*) callback_on_packet;

	/* Call function */
	self->on_packet(args, header, packet);
}

