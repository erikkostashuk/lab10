CFLAGS = -Wall -g

packet-sniffing: packet-sniffing.o
	cc -o packet-sniffing packet-sniffing.o -lpcap

clean :
	rm packet-sniffing.o packet-sniffing
