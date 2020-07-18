CC = gcc 
CFLAGS = 
LDFLAGS = -lcrypto

all: server

server: server.c websocket.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
    
clean:
	rm -f server

