CC = gcc
CFLAGS = -Wall -Wextra -g -I./headers -I/usr/local/ssl/include
LDFLAGS = -L/usr/local/ssl/lib64 -lssl -lcrypto
SOURCES = $(wildcard ./src/*.c)
OBJECTS = $(SOURCES:./src/%.c=./build/%.o)
EXECUTABLE = ./build/main

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $^ -o $@

./build/%.o: ./src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(EXECUTABLE) $(OBJECTS)

