/* Author: Brad Powell
 * Date: 6/3/2019
 * One Time Pad Encoder
 * Usage: otp_enc plaintext key port
 * This program connects to the encoder daemon at 'port', sends it 'plaintext' and 'key', and prints
 * out the received ciphertext to stdout.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

void error(const char *msg) { perror(msg); exit(1); } // Error function for reporting issues.

int main(int argc, char *argv[]) {
	// Variables for client networking
	int socketFD, portNumber, charsWritten, charsRead;
	struct sockaddr_in serverAddress;
	struct hostent* serverHostInfo;
	char buffer[256];

	// Variables for string processing
	char* inPlain = NULL;
	char* inKey = NULL;
	size_t inputSize = 0;
	int numPlain, numKey;
	int i;

	if (argc != 4) { fprintf(stderr, "USAGE: %s plaintext key port\n", argv[0]); exit(1); } // Check usage/args

/************** String retrieval ************************/
	FILE* fp = fopen(argv[1], "r");
	numPlain = getline(&inPlain, &inputSize, fp);	// Read plaintext file
	fclose(fp);
	// Check for bad characters. Goes to charsRead-1 to ignore newline.
	for (i = 0; i < numPlain-1; i++){
		if ((inPlain[i] < 65 || inPlain[i] > 90) && inPlain[i] != 32) {
			error("Bad character in plaintext");
		}
	}
	// Modify the text to have @@ as a terminator
	inPlain[numPlain-1] = '@';
	inPlain[numPlain] = '@';
	inPlain[numPlain+1] = '\0';

	// Repeat for key
	fp = fopen(argv[2], "r");
	numKey = getline(&inKey, &inputSize, fp);
	fclose(fp);
	if (numPlain > numKey) error("ERROR: plaintext longer than key");	// Verify longer key than text
	for (i = 0; i < numKey-1; i++) {
		if ((inKey[i] < 65 || inKey[i] > 90) && inKey[i] != 32) {
			error("Bad character in key");
		}
	}
	inKey[numKey-1] = '@';
	inKey[numKey] = '@';
	inKey[numKey+1] = '\0';


/************** Network Connection **********************/

	// Set up the server address struct
	memset((char*)&serverAddress, '\0', sizeof(serverAddress));	// Clear address struct
	portNumber = atoi(argv[3]);			// Convert port number to int
	serverAddress.sin_family = AF_INET;		// Create network-capable socket
	serverAddress.sin_port = htons(portNumber);	// Store the port number
	serverHostInfo = gethostbyname("localhost");	// Convert machine name to special form of address
	// Copy the host address
	memcpy((char*)&serverAddress.sin_addr.s_addr, (char*)serverHostInfo->h_addr, serverHostInfo->h_length);

	// Set up the socket
	socketFD = socket(AF_INET, SOCK_STREAM, 0);	// Create the socket
	if (socketFD < 0) error("ERROR opening socket");

	// Connect to server
	if (connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) //Connect socket to addy
		error("ERROR connecting");

/*************** Verify connection to correct server ********/
	charsWritten = send(socketFD, "secret", 6, 0);
	memset(buffer, '\0', sizeof(buffer));
	charsRead = recv(socketFD, buffer, sizeof(buffer)-1, 0);
	if (strcmp(buffer, "confirm") != 0) error ("ERROR connected to wrong server");


/**************** Send plaintext and key ********************/
	// Send plaintext
	charsWritten = 0;	// Set to 0 before loop
	do {
		// Send the remaining data (or try to send all of it if first go through).
		// &inPlain[charsWritten] gives us the address of the remaining string - either
		// &inPlain[0] to begin, or wherever it stopped if it go interrupted.
		// Only sends the size of the buffer each time, so larger messages are broken up.
		memset(buffer, '\0', sizeof(buffer));
		strncpy(buffer, &inPlain[charsWritten], sizeof(buffer)-1);
		charsWritten += send(socketFD, buffer, strlen(buffer), 0);
	} while(charsWritten < strlen(inPlain));	// Repeat until all data is sent

	// Receive confirm to stay in sync
	recv(socketFD, buffer, sizeof(buffer)-1, 0);

	// Send Key
	charsWritten = 0;
	do {
		memset(buffer, '\0', sizeof(buffer));
		strncpy(buffer, &inKey[charsWritten], sizeof(buffer)-1);
		charsWritten += send(socketFD, buffer, strlen(buffer), 0);
	} while(charsWritten < strlen(inKey));

	memset(buffer, '\0', sizeof(buffer));
	recv(socketFD, buffer, sizeof(buffer)-1, 0);
	printf("CLIENT: from server: %s\n", buffer);


/* demo data
	// send message
	charsWritten = send(socketFD, buffer, strlen(buffer), 0);
	if (charsWritten < 0) error("ERROR writing to socket");
	if (charsWritten < strlen(buffer)) printf("ClIENT: WARNING: not all data written\n");

	// get return message
	memset(buffer, '\0', sizeof(buffer));
	charsRead = recv(socketFD, buffer, sizeof(buffer)-1, 0);
	if (charsRead < 0) error("CLIENT: ERROR reading from socket");
	printf("CLIENT: I received from server: %s\n", buffer);

	close(socketFD);

end demo data	*/



	return 0;
}
