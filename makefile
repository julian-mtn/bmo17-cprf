CC      = gcc
CFLAGS  = -Wall -Wextra -O2
LIBS    = -lcrypto

SRC_DIR = sources
INC_DIR = include

# Sources communes BMO17
COMMON_BMO17 = $(SRC_DIR)/bmo17.c \
               $(SRC_DIR)/rsa.c \
               $(SRC_DIR)/rabin.c \
               $(SRC_DIR)/lazy_sampling.c

# Sources FWEAK
COMMON_FWEAK = $(SRC_DIR)/fweak.c

# Serveur et attaque
SERVER_BMO17_SRC = $(SRC_DIR)/oracle_bmo17.c
ATTACK_BMO17_SRC = $(SRC_DIR)/attack_bmo17.c

SERVER_FWEAK_SRC = $(SRC_DIR)/oracle_fweak.c
ATTACK_FWEAK_SRC = $(SRC_DIR)/attack_fweak.c

TEST_SRC        = $(SRC_DIR)/tests.c

# Binaries
SERVER_BMO17    = server_bmo17
ATTACK_BMO17    = attack_bmo17

SERVER_FWEAK    = server_fweak
ATTACK_FWEAK    = attack_fweak

TEST            = tests

# ==================== Rules ====================
all: $(SERVER_BMO17) $(ATTACK_BMO17) $(SERVER_FWEAK) $(ATTACK_FWEAK) $(TEST)

# BMO17
$(SERVER_BMO17): $(SERVER_BMO17_SRC) $(COMMON_BMO17)
	$(CC) $(CFLAGS) -I$(INC_DIR) $^ -o $@ $(LIBS)

$(ATTACK_BMO17): $(ATTACK_BMO17_SRC) $(COMMON_BMO17)
	$(CC) $(CFLAGS) -I$(INC_DIR) $^ -o $@ $(LIBS)

# FWEAK
$(SERVER_FWEAK): $(SERVER_FWEAK_SRC) $(COMMON_FWEAK)
	$(CC) $(CFLAGS) -I$(INC_DIR) $^ -o $@ $(LIBS)

$(ATTACK_FWEAK): $(ATTACK_FWEAK_SRC) $(COMMON_FWEAK)
	$(CC) $(CFLAGS) -I$(INC_DIR) $^ -o $@ $(LIBS)

# Tests
$(TEST): $(TEST_SRC) $(COMMON_BMO17)
	$(CC) $(CFLAGS) -I$(INC_DIR) $^ -o $@ $(LIBS)

clean:
	rm -f $(SERVER_BMO17) $(ATTACK_BMO17) $(SERVER_FWEAK) $(ATTACK_FWEAK) $(TEST) *.o