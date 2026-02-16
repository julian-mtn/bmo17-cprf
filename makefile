CC      = gcc
CFLAGS  = -Wall -Wextra -O2
LIBS    = -lcrypto

SRC_DIR = sources
INC_DIR = include

COMMON_SRC = $(SRC_DIR)/bmo17.c \
             $(SRC_DIR)/rsa.c \
             $(SRC_DIR)/rabin.c \
             $(SRC_DIR)/lazy_sampling.c

SERVER_SRC = $(SRC_DIR)/server.c
ATTACK_SRC = $(SRC_DIR)/attack.c
TEST_SRC   = $(SRC_DIR)/tests.c

SERVER = server
ATTACK = attack
TEST   = tests

all: $(SERVER) $(ATTACK) $(TEST)

$(SERVER): $(SERVER_SRC) $(COMMON_SRC)
	$(CC) $(CFLAGS) -I$(INC_DIR) $^ -o $@ $(LIBS)

$(ATTACK): $(ATTACK_SRC) $(COMMON_SRC)
	$(CC) $(CFLAGS) -I$(INC_DIR) $^ -o $@ $(LIBS)

$(TEST): $(TEST_SRC) $(COMMON_SRC)
	$(CC) $(CFLAGS) -I$(INC_DIR) $^ -o $@ $(LIBS)

clean:
	rm -f $(SERVER) $(ATTACK) $(TEST) *.o
