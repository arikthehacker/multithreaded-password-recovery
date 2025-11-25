# holy chopped makefile!!!!
# cs333 Lab 3 - thread_hash

CC      = gcc
CFLAGS  = -g \
          -Wall -Wextra -Wshadow -Wunreachable-code \
          -Wredundant-decls -Wmissing-declarations \
          -Wold-style-definition -Wmissing-prototypes \
          -Wdeclaration-after-statement -Wno-return-local-addr \
          -Wunsafe-loop-optimizations -Wuninitialized -Werror \
          -Wno-unused-parameter \
          -pthread

CFLAGS += -Wno-string-compare -Wno-stringop-overflow \
          -Wno-stringop-overread -Wno-stringop-truncation

LDLIBS  = -lcrypt -pthread

TARGET  = thread_hash
OBJS    = thread_hash.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

thread_hash.o: thread_hash.c
	$(CC) $(CFLAGS) -c thread_hash.c

clean:
	rm -f $(TARGET) $(OBJS) core \
	      *~ \#* .\#*


run: $(TARGET)
	./$(TARGET) -i example-hashes.txt -d example-dict.txt

test:
	./test.sh

.PHONY: all clean run test
