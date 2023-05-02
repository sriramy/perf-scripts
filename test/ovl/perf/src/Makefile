BUILD	= build
SRC	= $(wildcard *.c)
BIN	= $(patsubst %.c,%,$(SRC))
CC	= gcc
CFLAGS	= -g -Wall -Werror
LDFLAGS	= 

all: $(BIN)

%.o: %.c
	mkdir -p $(BUILD)
	$(CC) -c $(CFLAGS) -o $(BUILD)/$@ $<

$(BIN): %: %.o
	$(CC) -o $(BUILD)/$@ $(BUILD)/$< $(CFLAGS) $(LDFLAGS)

clean:
	rm -rf $(BUILD)

.PHONY: clean
