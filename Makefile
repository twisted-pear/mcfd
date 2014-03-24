TEST_BIN= keccak_test
BINS	= $(TEST_BIN)

TEST_IN	= LongMsgKAT.txt MonteCarlo.txt ShortMsgKAT.txt
TEST_OUT= $(foreach type,LongMsgKAT MonteCarlo ShortMsgKAT,$(foreach size,224 256 384 512, $(type)_$(size).txt)) TestDuplex.txt
TEST_REF= test_expected/

LIBS	=

S_COMM	= sponge.c duplex.c common.c spongewrap.c main.c genKAT.c KeccakNISTInterface.c testDuplex.c
S_PERM	= KeccakF-1600.c 
S_PAD	= KeccakPad_10_1.c 

O_COMM	= $(S_COMM:.c=.o)
O_PERM	= $(S_PERM:.c=.o)
O_PAD	= $(S_PAD:.c=.o)

OBJS	= $(O_COMM) $(O_PERM) $(O_PAD)

CFLAGS	= -Wall -g
LDFLAGS	=

all: $(BINS)

test: $(TEST_BIN) $(TEST_IN)
	./$(TEST_BIN)
	status=0; \
	for f in $(TEST_OUT); do \
		diff -q $$f $(TEST_REF)/$$f; \
		ret=$$?; \
		[ $$ret -ne 0 ] && status=$$ret; \
	done; \
	exit $$status

$(TEST_BIN): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

$(O_PERM): $(S_PERM) permutation.h
	$(CC) $(CFLAGS) -o $@ -c $<

$(O_PAD): $(S_PAD) pad.h
	$(CC) $(CFLAGS) -o $@ -c $<

%.o: %.c %.h
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f $(OBJS) $(BINS) $(TEST_OUT)

.PHONY: all clean test
