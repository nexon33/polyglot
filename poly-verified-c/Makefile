CC      := gcc
CFLAGS  := -O2 -Wall -Wextra -Wno-unused-parameter
LDFLAGS := -lcrypto

LIB_SRC := poly_verified.c
LIB_HDR := poly_verified.h
LIB_OBJ := poly_verified.o

TEST_SRC := test_poly_verified.c
TEST_BIN := test_poly_verified

.PHONY: all test clean

all: $(TEST_BIN)

$(LIB_OBJ): $(LIB_SRC) $(LIB_HDR)
	$(CC) $(CFLAGS) -c $(LIB_SRC) -o $(LIB_OBJ)

$(TEST_BIN): $(TEST_SRC) $(LIB_OBJ) $(LIB_HDR)
	$(CC) $(CFLAGS) $(TEST_SRC) $(LIB_OBJ) -o $(TEST_BIN) $(LDFLAGS)

test: $(TEST_BIN)
	./$(TEST_BIN)

clean:
	rm -f $(LIB_OBJ) $(TEST_BIN)
