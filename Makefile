CC = gcc
CFLAGS = -c -Wall -g
OUTPUT_DIR = ./build/
SRC = $(wildcard src/*.c)
OBJ = $(patsubst src/%.c, %.o, $(SRC))
OBJ_OUT = $(patsubst src/%.c, $(OUTPUT_DIR)%.o, $(SRC))
INCLUDE = -I./src
LIB = -lev -lssl -lcrypto

TEST_SRC = $(wildcard test/*.c)
TEST_OBJ = $(patsubst test/%.c, %.o, $(TEST_SRC))

.PHONY:all clean test


all: $(OBJ) $(TEST_OBJ)
	@echo $(SRC)
	@echo $(OBJ)
	$(CC) $(OBJ_OUT) $(OUTPUT_DIR)test_cli.o -o $(OUTPUT_DIR)test_cli $(LIB)
	$(CC) $(OBJ_OUT) $(OUTPUT_DIR)test_serv.o -o $(OUTPUT_DIR)test_serv $(LIB)

%.o: src/%.c
	@echo $< $@
	$(CC) $(INCLUDE) $(CFLAGS) $< -o $(OUTPUT_DIR)$@

%.o: test/%.c
	@echo $< $@
	$(CC) $(INCLUDE) $(CFLAGS) $< -o $(OUTPUT_DIR)$@

clean:
	RM $(OUTPUT_DIR)*
