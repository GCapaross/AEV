CC = sudo docker run -ti --rm -v $(shell pwd):/root gcc:8 gcc

SRC=src
BIN=bin

SRCS=$(wildcard $(SRC)/*.c)
BINS=$(SRCS:$(SRC)/%.c=%)

all: $(BINS)

zip:
	zip -9r bo-stack.zip Makefile src bin

%: $(SRC)/%.c
	$(CC) -g -O0  -o /root/$(BIN)/$@ /root/$<
	$(CC) -g -O0 --static -o /root/$(BIN)/$@-static /root/$<


clean:
	$(RM) $(BIN)/*

