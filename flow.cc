/*
 * flow.cc
 *
 *  Created on: Mar 9, 2014
 *      Author: ctolooee
 */
#include <iostream>
#include <iomanip>
#include <string>
#include "flow.h"

Flow::Flow(Packet *packet, int expiration) :
		expiration(expiration) {
	start_time = getTime(packet->time_sec, packet->time_usec);
	protocol = convertProtocol(packet->protocol);
	if(protocol == "UDP")
		direction = FORWARD;
	else
		direction = BIDIR;
	fin_state = "NOFIN";
	source = packet->source;
	dest = packet->dest;
	sport = packet->sport;
	dport = packet->dport;
	total_packets = 1;
	total_bytes = packet->size;
	setState(packet);
	duration = 0;
}

Flow::~Flow() {
}

std::string convertProtocol(unsigned short proto) {
	std::string protocol;
	switch (proto) {
	case 1:
		protocol = "ICMP";
		break;
	case 6:
		protocol = "TCP";
		break;
	case 17:
		protocol = "UDP";
		break;
	default:
		protocol = "Other";  // should never reach this due to filter
	}
	return protocol;
}

bool Flow::isApartofFlow(Packet *p) {
	if (state == FIN)
		return false;
	int dur = getTime(p->time_sec, p->time_usec) - start_time;
	if (dur >= expiration) {
		return false;
	} else {
		/* english version:
		 * same protocol
		 * AND {
		 * 		sourses and dests (and corresponding ports) match
		 * 		OR
		 * 		swap source and dest (and corresponding ports) and check for matches
		 * }
		 */
		return convertProtocol(p->protocol) == protocol
				&& (((p->dest == dest && p->source == source
						&& p->sport == sport && p->dport == dport))
						|| ((p->dest == source && p->source == dest
								&& p->sport == dport && p->dport == sport)));
	}
}

double getTime(long sec, long usec) {
	double fracpart = usec / 1000000.0;
	return sec + fracpart;
}

void Flow::update(Packet *packet) {
	if (!isApartofFlow(packet)) { /* this packet does not belong to this flow */
		std::cerr << "Packet does not belong to the flow: " << this
				<< std::endl;
		return;
	}

	/* get duration and check for expiration */
	duration = getTime(packet->time_sec, packet->time_usec) - start_time;

	/* figure out state */
	setState(packet);
	/* update data */
	++total_packets;
	total_bytes += packet->size;

}

void Flow::setState(Packet *packet) {
	if (state == FIN)
		return;

	if (fin_state == "FIN1") {
		for (unsigned int i = 0; i < finacks.size(); ++i) {
			// if we find a matching ack to fin1 move to ack1
			if (finacks[i] == packet->ack_num - 1
					&& packet->flags.find("ACK") != std::string::npos) {
				finacks.erase(finacks.begin() +i);
				fin_state = "ACK1";
				state = EST;
			}
		}
	}
	if (fin_state == "ACK1") {
		// if see another FIN
		if (packet->flags.find("FIN") != std::string::npos) {
			finacks.push_back(packet->seq_num);
			fin_state = "FIN2";
			state = EST;
		}
	}
	if (fin_state == "FIN2") {
		for (unsigned int i = 0; i < finacks.size(); ++i) {
			// if we find a matching ack to fin2 move to completed
			if (finacks[i] == packet->ack_num - 1
					&& packet->flags.find("ACK") != std::string::npos) {
				fin_state = "DONE";
				state = FIN;
				return;
			}
		}
	}
		if (packet->protocol == 1) { // ICMP
			state = packet->flags;
		} else if (packet->protocol == 6) { // TCP
			if (packet->flags == "SYN ") {
				state = SYN;
				direction = FORWARD;
			} else if (packet->flags == "SYN ACK ") {
				state = SYNACK;
			} else if (packet->flags == "ACK ") {
				state = EST;
			} else if (packet->flags.find("FIN") != std::string::npos && fin_state == "NOFIN") {
				state = EST;
				fin_state = "FIN1";
				finacks.push_back(packet->seq_num);
			} else if (packet->flags.find("RST") != std::string::npos) {
				state = RST;
			}
		} else { // UDP or others
			if(packet->dest == source && packet->source == dest)
				direction = BIDIR;
			state = "";
		}
	}

std::ostream& operator<<(std::ostream& os, const Flow flow) {
	if(flow.sport != -1) {
		os << std::setiosflags(std::ios::fixed) << std::setw(18) << std::left
		<< flow.start_time << std::setw(6) << flow.protocol << std::setw(17)
		<< flow.source << std::setw(6) << flow.sport << std::setw(4)
		<< flow.direction << std::setw(17) << flow.dest << std::setw(9)
		<< flow.dport << std::setw(8) << flow.total_packets << std::setw(9)
		<< flow.total_bytes << std::setw(8) << flow.state << std::setw(15)
		<< flow.duration;
	} else {
		os << std::setiosflags(std::ios::fixed) << std::setw(18) << std::left
		<< flow.start_time << std::setw(6) << flow.protocol << std::setw(17)
		<< flow.source << std::setw(6) << "" << std::setw(4)
		<< flow.direction << std::setw(17) << flow.dest << std::setw(9)
		<< "" << std::setw(8) << flow.total_packets << std::setw(9)
		<< flow.total_bytes << std::setw(8) << flow.state << std::setw(15)
		<< flow.duration;
	}
	return os;
}
