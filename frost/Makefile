CC = gcc
CFLAGS = -Wall -Wextra -g -I./headers
LDFLAGS =  -lssl -lcrypto
SOURCES = $(wildcard ./src/*.c)
OBJECTS = $(SOURCES:./src/%.c=./build/%.o)
EXECUTABLE = ./build/main

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $^ -o $@ $(LDFLAGS)

./build/%.o: ./src/%.c
	$(CC)  -c $< -o $@ $(CFLAGS)

clean:
	rm -f $(EXECUTABLE) $(OBJECTS)

