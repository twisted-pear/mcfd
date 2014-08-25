#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <keccak/KeccakF-1600.h>
#include <keccak/KeccakPad_10_1.h>
#include "spongeprg.h"

static const char *progname = "keccak_rng";

static void usage(void)
{
	fprintf(stderr, "Usage: %s <seed> <outfile> [<nbytes>]\n", progname);
	exit(EXIT_FAILURE);
}

static unsigned char buf[1024];

int main(int argc, char *const *argv)
{
	int ret = EXIT_FAILURE;

	if (argc < 3 || argc > 4) {
		usage();
	}

	if (argv[0] == NULL) {
		usage();
	}

	progname = argv[0];

	char *seed = argv[1];
	char *outfile = argv[2];

	if (seed == NULL || outfile == NULL) {
		usage();
	}

	long long length = 0;

	if (argc == 4) {
		char *nbytes = argv[3];
		if (nbytes == NULL) {
			usage();
		}

		length = strtoll(nbytes, NULL, 10);
		if (length < 0 || errno != 0) {
			usage();
		}
	}

	FILE *outf = fopen(outfile, "wb");
	if (outf == NULL) {
		fprintf(stderr, "ERROR: Failed to open outfile.\n");
		return EXIT_FAILURE;
	}

	permutation *f = keccakF_1600_init();
	if (f == NULL) {
		fprintf(stderr, "ERROR: Failed to create permutation.\n");
		fclose(outf);
		return EXIT_FAILURE;
	}

	pad *p = keccakPad_10_1_init(1026);
	if (p == NULL) {
		fprintf(stderr, "ERROR: Failed to create pad.\n");
		fclose(outf);
		keccakF_1600_free(f);
		return EXIT_FAILURE;
	}

	spongeprg *g = spongeprg_init(f, p, 1026, 128);
	if (g == NULL) {
		fprintf(stderr, "ERROR: Failed to create RNG.\n");
		fclose(outf);
		keccakPad_10_1_free(p);
		keccakF_1600_free(f);
		return EXIT_FAILURE;
	}

	if (spongeprg_feed(g, (unsigned char *) seed, strlen(seed)) != 0) {
		fprintf(stderr, "ERROR: Failed to seed PRG.\n");
		goto out;
	}

	if (length == 0) {
		for (;;) {
			if (spongeprg_fetch(g, buf, sizeof(buf)) != 0) {
				fprintf(stderr, "ERROR: Fetch failed.\n");
				goto out;
			}

			if (fwrite(buf, 1, sizeof(buf), outf) != sizeof(buf)) {
				fprintf(stderr, "ERROR: Failed to write.\n");
				goto out;
			}
		}
	}

	while ((size_t) length > sizeof(buf)) {
		if (spongeprg_fetch(g, buf, sizeof(buf)) != 0) {
			fprintf(stderr, "ERROR: Fetch failed.\n");
			goto out;
		}

		if (fwrite(buf, 1, sizeof(buf), outf) != sizeof(buf)) {
			fprintf(stderr, "ERROR: Failed to write.\n");
			goto out;
		}

		length -= sizeof(buf);
	}

	if (spongeprg_fetch(g, buf, length) != 0) {
		fprintf(stderr, "ERROR: Fetch failed.\n");
		goto out;
	}

	if (fwrite(buf, 1, length, outf) != (size_t) length) {
		fprintf(stderr, "ERROR: Failed to write.\n");
		goto out;
	}

	ret = EXIT_SUCCESS;

out:
	fclose(outf);
	spongeprg_free(g);
	keccakPad_10_1_free(p);
	keccakF_1600_free(f);

	return ret;
}
