CC = gcc
CFLAGS = -lz -lcurl -lpthread 
EXEC = ./app/server
FILE = ./app/server.c

./app/server: ./app/server.c
	$(CC) -o $(EXEC) $(FILE) $(CFLAGS)

run:
	./app/server

clean:
	rm ./app/server
