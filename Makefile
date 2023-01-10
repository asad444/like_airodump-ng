all: like_airodump-ng

like_airodump-ng: main.o
	g++ -o like_airodump-ng main.o -lpcap

main.o:	main.cpp

clean:
	rm -f *.o like_airodump-ng
