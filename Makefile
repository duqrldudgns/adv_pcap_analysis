all : pcap_test

pcap_test: main.o pcap.h
	g++ -g -w -o pcap_test main.o pcap.h -lpcap

main.o: main.c
	g++ -g -c -o main.o main.c -lpcap

clean:
	rm -f pcap_test
	rm -f *.o

