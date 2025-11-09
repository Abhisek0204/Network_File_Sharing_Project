CXX = g++
CXXFLAGS = -std=c++17 -O2 -Wall -pthread
LDFLAGS = -lssl -lcrypto

TARGETS = server client

all: $(TARGETS)

server: server.cpp
	$(CXX) $(CXXFLAGS) server.cpp -o server $(LDFLAGS)

client: client.cpp
	$(CXX) $(CXXFLAGS) client.cpp -o client $(LDFLAGS)

clean:
	rm -f $(TARGETS)
