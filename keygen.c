/* Author: Brad Powell
 * Date: 6/3/09
 * Keygen - Use: "keygen keylength"
 * Generates a string of random uppercase characters and spaces to be used as a one-time pad.
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

int main (int argc, char *argv[]) {
	srand(time(0));		// Randomize seed
	int	keylength, i,	// Length of key and loop counter
		ascii;		// Holder for randomized ASCII character
	char key[500];		// Buffer for generated key
	memset(key, '\0', sizeof(key));
	
	// Verify use as "keygen keylength"
	if (argc != 2) {
		fprintf(stderr, "USAGE: %s keylength\n", argv[0]);
		exit(1);
	}

	keylength = atoi(argv[1]);	// Convert string of keylength to int
	for (i = 0; i < keylength; i++) {
		ascii = 65 + (rand() % 27);	// Set ascii to 65-91, which is A-[
		if (ascii == 91) { ascii = 32; } // Convert [ to space
		key[i] = ascii;			// Append character to the key
	}

	key[i] = '\n';	// Add newline

	// Print key to stdout
	fprintf(stdout, "%s", key);

	return 0;
}
