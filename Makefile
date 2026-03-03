CC = gcc
CFLAGS = -O2 -Wall -Iinclude -Icrypto
LIBS = -lcrypto -lssl

OBJECTS = src/fake_tls.o src/routing.o src/handshake.o src/encrypt.o src/tunnel.o src/client.o src/server.o crypto/keygen.o

all: client server

client: src/fake_tls.o src/routing.o src/handshake.o src/encrypt.o src/tunnel.o src/client.o crypto/keygen.o
	$(CC) $^ -o client $(LIBS)

server: src/fake_tls.o src/routing.o src/handshake.o src/encrypt.o src/tunnel.o src/server.o crypto/keygen.o
	$(CC) $^ -o server $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) client server
