/*
 * flow.h
 *
 *  Created on: Mar 9, 2014
 *      Author: ctolooee
 */
#ifndef FLOW_H_
#define FLOW_H_
#include <iostream>
#include <vector>
#include <netinet/tcp.h>


/* direction constants */
#define FORWARD " ->"
#define BACKWARD "<-"
#define BIDIR "<->"

/* tcp state constants */
#define SYN "SYN"
#define SYNACK "SYNACK"
#define EST "EST"
#define FIN "FIN"
#define RST "RST"

struct Packet {
	unsigned long time_sec;
	unsigned long time_usec;
	unsigned short protocol;
	std::string source;
	std::string dest;
	int sport;
	int dport;
	std::string flags;
	unsigned int size;
	unsigned long ack_num;
	unsigned long seq_num;
};

double getTime(long, long);
std::string convertProtocol(unsigned short);

class Flow {
public:
	int expiration;
	double start_time;
	std::string protocol;
	std::string source;
	std::string dest;
	std::string direction;
	int sport;
	int dport;
	long total_packets;
	long total_bytes;
	std::string state;
	double duration;
	Flow(Packet *packet, int expiration);
	~Flow();
	bool isApartofFlow(Packet *packet);
	void update(Packet *packet);

private:
	std::string fin_state;
	std::vector<unsigned long> finacks;
	void setState(Packet *);
};
std::ostream& operator<<(std::ostream& os, const Flow flow);

#endif /* FLOW_H_ */

