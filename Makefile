CC=g++

CFLAGS+=-Wall -W -g -I /usr/local/opt /usr/local/opt/openssl/lib/libcrypto.a 

all: server client

client: client.c
	$(CC) client.c encryption.c $(CFLAGS) -o client

server: server.c
	$(CC) server.c encryption.c $(CFLAGS) -o server


clean:
	rm -f server client *.o

