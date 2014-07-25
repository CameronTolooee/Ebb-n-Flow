/*
 * sniffer.h
 *
 *  Created on: Mar 7, 2014
 *      Author: ctolooee
 */
#ifndef	SNIFFER_H_
#define SNIFFER_H_
#include <string>
#include <pcap.h>
#include "flow_table.h"

class Sniffer {

public:
	FlowTable flow_table;
	Sniffer(int, int);
	~Sniffer();
	void alarm_handler();
	static void alarm_handler_wrapper(int i);
	void readFile(std::string filename, int offset, unsigned int time);
	void readInterface(std::string interface, unsigned int time);
	int sniff(pcap_t *handle, int offset, unsigned int time);
	std::string getFlags(const struct tcphdr *tcp);
	void on_packet(unsigned char *args, const struct pcap_pkthdr* header,
			const unsigned char* packet);
	static void on_packet_wrapper(unsigned char *args,
			const struct pcap_pkthdr* header, const unsigned char* packet);
private:
	unsigned int count;
	std::string name;
	pcap_t *handle;
	struct _info {
		unsigned int time;
		int offset;
		unsigned long start;
	};
	typedef struct _info Info;
};
#endif /* SNIFFER_H_ */

