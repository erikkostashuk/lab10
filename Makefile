CFLAGS = -Wall -g

lab10: lab10.o
	cc -o lab10 lab10.o -lpcap

clean :
	rm lab10.o lab10
