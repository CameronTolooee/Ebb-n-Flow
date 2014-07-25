/*
 * main.cpp
 *
 *  Created on: Mar 7, 2014
 *      Author: ctolooee
 */
#include "sniffer.h"
#include <stdlib.h>
#include <unistd.h>
#include <iostream>

using namespace std;
#define TEST
#ifdef TEST

bool is_number(char *c) {
    int i = 0;
    while (c[i] != 0) {
    	if(c[i] < '0' || c[i] > '9') {
    		return false;
    	}
    	++i;
    }
    return true;
}

int main(int argc, char **argv) {
	if (argc < 2) {
		printf(
				"usage: sniffer [-r filename] [-i interface] [-t time] [-o time_offset] [-N num] [-S secs]\n");
		return 2;
	}
// Flags for opts
	string filename = "";
	int rFlag = 0;
	string interface = "";
	int iFlag = 0;
	int time = -1;
	int offset = -1;
	int opt;
	int N = -1;
	int S = 60; // default value of 60
// stolen and modified from GNU Getopt manual -- http://www.gnu.org/software/libc/manual/html_node/Getopt.html
	while ((opt = getopt(argc, argv, "r:i:t:o:S:N:")) != -1) {
		switch (opt) {
			case 'r':
				filename = optarg;
				rFlag = 1;
				break;
			case 'i':
				interface = optarg;
				iFlag = 1;
				break;
			case 't':
				if(is_number(optarg))
					time = atoi(optarg);
				else {
					cerr << "invalid argument" << endl;
					return 1;
				}
				break;
			case 'o':
				if(is_number(optarg))
					offset = atoi(optarg);
				else {
					cerr << "invalid argument" << endl;
					return 1;
				}
				break;
			case 'N':
				if(is_number(optarg))
					N = atoi(optarg);
				else {
					cerr << "invalid argument" << endl;
					return 1;
				}
				break;
			case 'S':
				if(is_number(optarg))
					S = atoi(optarg);
				else {
					cerr << "invalid argument" << endl;
					return 1;
				}
				break;
			case '?':
				if (optopt == 'r' || optopt == 'i' || optopt == 't'
						|| optopt == 'o')
					fprintf(stderr, "Option -%c requires an argument.\n",
							optopt);
				else if (isprint(optopt))
					fprintf(stderr, "Unknown option `-%c'.\n", optopt);
				else
					fprintf(stderr, "Unknown option character `\\x%x'.\n",
							optopt);
				return 1;
			default:
				abort();
		}
	}
// check for invalid getop combinations
	if (rFlag && iFlag) { //  interface and file (should be mutually exclusive)
		fprintf(stderr, "Cannot read from both a file and an interface.\n");
		return 1;
	} else if (!rFlag && !iFlag) {
		fprintf(stderr,
				"Must specify what to sniff (filename or interface).\n");
		return 1;
	} else if (iFlag && time == -1) {
		fprintf(stdout, "No time specified, defaulting to 10s\n\n");
		time = 10;
	}

	Sniffer s(N, S);
	if (rFlag) {
		if(offset == -1) offset = 0;
		string name(filename);
		s.readFile(name, offset, time);
	} else {
		string name(interface);
		s.readInterface(name, time);
	}
	cout << s.flow_table << endl;
	return 0;
}
#endif

