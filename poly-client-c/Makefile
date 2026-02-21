CC      := gcc
CFLAGS  := -O2 -Wall -Wextra -Wno-unused-parameter
LDFLAGS := -lcrypto

VERIFIED_DIR := ../poly-verified-c
VERIFIED_OBJ := $(VERIFIED_DIR)/poly_verified.o

CLIENT_SRC := poly_client.c
CLIENT_HDR := poly_client.h
CLIENT_OBJ := poly_client.o

TEST_SRC := test_poly_client.c
TEST_BIN := test_poly_client

.PHONY: all test clean verified

all: $(TEST_BIN)

verified:
	$(MAKE) -C $(VERIFIED_DIR) $(VERIFIED_DIR)/poly_verified.o

$(VERIFIED_OBJ): verified

$(CLIENT_OBJ): $(CLIENT_SRC) $(CLIENT_HDR) $(VERIFIED_DIR)/poly_verified.h
	$(CC) $(CFLAGS) -I$(VERIFIED_DIR) -c $(CLIENT_SRC) -o $(CLIENT_OBJ)

$(TEST_BIN): $(TEST_SRC) $(CLIENT_OBJ) $(VERIFIED_OBJ) $(CLIENT_HDR)
	$(CC) $(CFLAGS) -I$(VERIFIED_DIR) $(TEST_SRC) $(CLIENT_OBJ) $(VERIFIED_OBJ) -o $(TEST_BIN) $(LDFLAGS)

test: $(TEST_BIN)
	./$(TEST_BIN)

clean:
	rm -f $(CLIENT_OBJ) $(TEST_BIN)
