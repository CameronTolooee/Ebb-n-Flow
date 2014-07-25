/*
 * flow_table.cpp
 *
 *  Created on: Mar 9, 2014
 *      Author: ctolooee
 */
#include "flow_table.h"

FlowTable::FlowTable(int max, int time_between) : max_entries(max), time_between(time_between) { }

FlowTable::~FlowTable() {
}

void FlowTable::update(Packet * packet) {
	std::vector<Flow>::iterator it;
	bool new_flow = true;
	for(it = table.begin(); it != table.end(); ++it) {
		if ((*it).isApartofFlow(packet)) {
			(*it).update(packet);
			new_flow = false;
			return;
		}
	}
	if (new_flow) {
		add(Flow(packet, time_between));
	}
}

void FlowTable::add(Flow f) {
	table.push_back(f);
}

int FlowTable::size(){
	return table.size();
}

std::ostream& operator<<(std::ostream& os, FlowTable flow_table) {
	os << "StartTime        Proto   SrcAddr         Sport Dir  DstAddr        Dport   TotPkts  TotBytes State    Dur\n";
	int upper = flow_table.max_entries;
	if (upper == -1) {
		upper = flow_table.size();
	} else if(flow_table.size() < upper){
		upper = flow_table.size();
	}
	for (int i = 0; i < upper; ++i) {
		os << flow_table.table[i] << "\n";
	}
	return os;
}

//#define TEST2
#ifdef TEST2
int main() {
	Packet p = {1156534266, 654692000, 6, "192.168.1.1", "192.168.1.2", 72,
		10001, "SYN ACK ", 66};
	Packet p2 = {1156534280, 654692000, 6, "192.168.1.2", "192.168.1.1", 10001,
		72, "ACK ", 128};
	Packet p3 = {1156534280, 654692000, 6, "192.168.1.2", "192.168.1.1", 72,
		10001, "ACK ", 128};
	FlowTable table;

	table.update(&p);
	table.update(&p2);
	table.update(&p3);

	Flow flow(&p, 15);
	flow.update(&p2);
	std::cout << table << std::endl;
}
#endif
