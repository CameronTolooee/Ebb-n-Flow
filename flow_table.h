/*
 * flow_table.h
 *
 *  Created on: Mar 9, 2014
 *      Author: ctolooee
 */

#ifndef	FLOWTABLE_H_
#define FLOWTABLE_H_
#include <vector>
#include <string>
#include <iostream>
#include "flow.h"
class FlowTable {
public:
	std::vector<Flow> table;
	int max_entries;
	int time_between;
	FlowTable(int max, int time_between);
	~FlowTable();
	void add(Flow);
	void update(Packet *);
	int size();
private:

};
std::ostream& operator<<(std::ostream& os, const FlowTable table);
#endif /* FLOWTABLE_H_ */

