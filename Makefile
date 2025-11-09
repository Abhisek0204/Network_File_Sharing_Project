CXX = g++
CXXFLAGS = -std=c++17 -O2 -Wall -pthread
TARGETS = server client

all: $(TARGETS)

server: server.cpp
	$(CXX) $(CXXFLAGS) server.cpp -o server

client: client.cpp
	$(CXX) $(CXXFLAGS) client.cpp -o client

clean:
	rm -f $(TARGETS)
