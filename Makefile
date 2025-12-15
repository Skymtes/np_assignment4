all: mycurl

mycurl: myCurl.cpp
	g++ -Wall -O2 -pthread -o mycurl myCurl.cpp -lboost_system -lssl -lcrypto

clean:
	rm -f mycurl