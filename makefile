CC = gcc
CFLAGS = -Wall -Wextra -O2
LIBS = -lcrypto
TARGET = bmo17

all:
	$(CC) $(CFLAGS) ./sources/*.c -o $(TARGET) $(LIBS)

clean:
	rm -f $(TARGET) *.o a.out
