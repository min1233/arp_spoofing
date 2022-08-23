all : send_arp

send_arp: main.o
	g++ -g -o ./arp_spoofing main.o -lpcap -lpthread

main.o:
	g++ -g -c -o main.o main.cpp

clean:
	rm -f ./arp_spoofing
	rm -f ./*.o

