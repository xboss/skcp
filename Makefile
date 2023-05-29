CC = gcc
CFLAGS = -c -Wall -g
OUTPUT_DIR = ./build/
SRC = $(wildcard src/*.c)
OBJ = $(patsubst src/%.c, %.o, $(SRC))
OBJ_OUT = $(patsubst src/%.c, $(OUTPUT_DIR)%.o, $(SRC))
INCLUDE = -I./src
LIB = -lev -lssl -lcrypto -lpthread

TEST_SRC = $(wildcard test/*.c)
TEST_OBJ = $(patsubst test/%.c, %.o, $(TEST_SRC))

.PHONY:all clean test


all: $(OBJ) $(TEST_OBJ)
	@echo $(SRC)
	@echo $(OBJ)
	$(CC) $(OBJ_OUT) $(OUTPUT_DIR)skcp_client.o -o $(OUTPUT_DIR)skcp_client $(LIB)
	$(CC) $(OBJ_OUT) $(OUTPUT_DIR)skcp_server.o -o $(OUTPUT_DIR)skcp_server $(LIB)

%.o: src/%.c
	@echo $< $@
	$(CC) $(INCLUDE) $(CFLAGS) $< -o $(OUTPUT_DIR)$@

%.o: test/%.c
	@echo $< $@
	$(CC) $(INCLUDE) $(CFLAGS) $< -o $(OUTPUT_DIR)$@

clean:
	rm -rf $(OUTPUT_DIR)*
