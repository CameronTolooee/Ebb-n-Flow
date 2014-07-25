#~#############################################~#
# Cameron Tolooee                               #
# Make file for (almost) all simple c++ builds  #
# Change compile flags, link flags, and sources #
# to match your project needs.                  #
#~#############################################~#
CC=g++
CFLAGS=-c -Wall -Wextra -Wpedantic
LDFLAGS=-lpcap
SOURCES=main.cc flow.cc flow_table.cc sniffer.cc
OBJECTS=$(SOURCES:.cc=.o)
EXECUTABLE=fsniffer

all: $(SOURCES) $(EXECUTABLE)
	
$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.cc.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf *.o $(EXECUTABLE)


