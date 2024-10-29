CC = gcc
CFLAGS = -Wall -Wextra -g -I./headers
LDFLAGS = -lssl -lcrypto
SOURCES = $(wildcard ./src/*.c)
OBJECTS = $(SOURCES:./src/%.c=./build/%.o)
EXECUTABLE = ./build/main

# Top-level rule for building the executable
all: build_dir $(EXECUTABLE)

# Rule for building the executable
$(EXECUTABLE): $(OBJECTS)
	$(CC) $^ -o $@ $(LDFLAGS)

# Rule for compiling each object file and placing it in the build directory
./build/%.o: ./src/%.c | build_dir
	$(CC) -c $< -o $@ $(CFLAGS)

# Rule for creating the build directory if it doesn't exist
build_dir:
	mkdir -p ./build

# Rule for cleaning up the build artifacts
clean:
	rm -f $(EXECUTABLE) $(OBJECTS)

