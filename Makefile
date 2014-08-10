TEST_BIN= keccak_test
MCFD_BIN= mcfd
RNG_BIN	= keccak_rng
BINS	= $(TEST_BIN) $(MCFD_BIN) $(RNG_BIN)

TEST_IN	= LongMsgKAT.txt MonteCarlo.txt ShortMsgKAT.txt
TEST_OUT= $(foreach type,LongMsgKAT MonteCarlo ShortMsgKAT,$(foreach size,224 256 384 512, $(type)_$(size).txt)) TestDuplex.txt
TEST_REF= test_expected/

LIBS	=

S_TEST	= main.c genKAT.c KeccakNISTInterface.c testDuplex.c testSpongeWrap.c testSpongePRG.c
S_MCFD	= mcfd_auth.c mcfd_common.c mcfd_crypto.c mcfd_main.c mcfd_net.c 
S_RNG	= keccak_rng.c
S_COMM	= sponge.c duplex.c crypto_helpers.c spongewrap.c spongeprg.c
S_PERM	= KeccakF-1600.c 
S_PAD	= KeccakPad_10_1.c 

O_TEST	= $(S_TEST:.c=.o)
O_MCFD	= $(S_MCFD:.c=.o)
O_RNG	= $(S_RNG:.c=.o)
O_COMM	= $(S_COMM:.c=.o)
O_PERM	= $(S_PERM:.c=.o)
O_PAD	= $(S_PAD:.c=.o)

OS_TEST	= $(O_COMM) $(O_PERM) $(O_PAD) $(O_TEST)
OS_MCFD	= $(O_COMM) $(O_PERM) $(O_PAD) $(O_MCFD)
OS_RNG	= $(O_COMM) $(O_PERM) $(O_PAD) $(O_RNG)

OBJS	= $(O_COMM) $(O_PERM) $(O_PAD) $(O_TEST) $(O_MCFD) $(O_RNG)

CFLAGS	= -Wall -pedantic -std=c99 -D_XOPEN_SOURCE=500 -g
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

$(TEST_BIN): $(OS_TEST)
	$(CC) $(LDFLAGS) -o $@ $(OS_TEST) $(LIBS)

$(MCFD_BIN): $(OS_MCFD)
	$(CC) $(LDFLAGS) -o $@ $(OS_MCFD) $(LIBS)

$(RNG_BIN): $(OS_RNG)
	$(CC) $(LDFLAGS) -o $@ $(OS_RNG) $(LIBS)

$(O_PERM): $(S_PERM) permutation.h
	$(CC) $(CFLAGS) -o $@ -c $<

$(O_PAD): $(S_PAD) pad.h
	$(CC) $(CFLAGS) -o $@ -c $<

%.o: %.c %.h
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f $(OBJS) $(BINS) $(TEST_OUT)

.PHONY: all clean test
