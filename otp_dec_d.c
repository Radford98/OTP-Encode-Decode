/* Author: Brad Powell
 * Date: 6/4/2019
 * otp_dec_d: One Time Pad Decode Daemon
 * Use: otp_dec_d listening_port
 * Sets up a 'server' that listens for otp_dec in order to decode its message.
 * The children processes set up by the server will accept the ciphertext and key from otp_dec through
 * communication sockets and writes back the plaintext.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <netinet/in.h>

void error(const char *msg) {perror(msg); exit(1); }	// Error functions for reporting issues

int main (int argc, char *argv[]) {
	// Variables for server handling
	int listenSocketFD, estConnFD, portNumber, charsRead, charsWritten;
	socklen_t sizeOfClientInfo;
	char buffer[256];
	char completeCipher[70500];	// Must be large enough for ciphertext
	char completeKey[70500];
	struct sockaddr_in serverAddress, clientAddress;

	// Variables for managing children
	pid_t spawnid = -5;
	int childExitMethod = -5;
	pid_t pidArr[5];
	int numChild = 0;
	int i, reap;	// Index in for loop; Int for waitpid

	if (argc != 2) { fprintf(stderr, "USAGE: %s port\n", argv[0]); exit(1); }	// Check usage/args

	// Set up the server address struct
	memset((char *)&serverAddress, '\0', sizeof(serverAddress));	// Clear out the address struct
	portNumber = atoi(argv[1]);			// Convert port number to int
	serverAddress.sin_family = AF_INET;		// Create network-capable socket
	serverAddress.sin_port = htons(portNumber);	// Store the port number
	serverAddress.sin_addr.s_addr = INADDR_ANY;	// Any address is allowed to connect

	// Set up the socket
	listenSocketFD = socket(AF_INET, SOCK_STREAM, 0);	// Create the socket
	if (listenSocketFD < 0) error("ERROR openeing socket");

	// Enable the socket for listening
	// Connect socket to port
	if (bind(listenSocketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
		error("ERROR on binding");
	listen(listenSocketFD, 5);	// Flip the socket on, able to receive 5 connections

	while (1) {
		// Check if process slots have opened up
		// Loop through array of child processes - if they have finished then remove them from the array
		// and modify numChild to reflect this, and i so no children are skipped due to loop math.
		for (i = 0; i < numChild; i++){
			reap = waitpid(pidArr[i], &childExitMethod, WNOHANG);
			if (reap != 0) {
				pidArr[i] = pidArr[numChild-1];
				numChild--;
				i--;
			}
		}
		// Only 5 connections are allowed at a time. If full, wait a second then go back to the top
		// of the loop to check for any finished children.
		if (numChild == 5) {
			sleep(1);
			continue;
		}

		// Accept a connection, blocking if one is not available until one connects
		sizeOfClientInfo = sizeof(clientAddress);	// Get the size of the client address
		estConnFD = accept(listenSocketFD, (struct sockaddr *)&clientAddress, &sizeOfClientInfo); // Accept
		if (estConnFD < 0) {
			fprintf(stderr, "ERROR on accept\n");
			continue;	// Return to beginning of loop
		}

		spawnid = fork();
		switch (spawnid) {
			case -1:
				fprintf(stderr, "ERROR fork failed\n");
				break;
			case 0:		// Child (decrypting) process

				// Verify connection
				memset(buffer, '\0', 256);
				// First message should be small enough that it shouldn't be split up
				charsRead = recv(estConnFD, buffer, 255, 0);
				if (charsRead <0) error("ERROR reading from socket");
				if (strcmp(buffer, "message") != 0) {	// Reject connection
					charsWritten = send(estConnFD, "reject", 6, 0);
					close(estConnFD);
					exit(0);
				}
				charsWritten = send(estConnFD, "confirm", 7, 0);

				// Receive ciphertext
				memset(completeCipher, '\0', sizeof(completeCipher));
				while (strstr(completeCipher, "@@") == NULL) {
					memset(buffer, '\0', sizeof(buffer));		// Clear buffer
					charsRead = recv(estConnFD, buffer, 255, 0);	// Grab chunk of text
					strcat(completeCipher, buffer);			// Build message	
				}

				// Send confirm to stay in sync
				send(estConnFD, "confirm", 7, 0);

				// Receive key
				memset(completeKey, '\0', sizeof(completeKey));
				while (strstr(completeKey, "@@") == NULL) {
					memset(buffer, '\0', sizeof(buffer));
					charsRead = recv(estConnFD, buffer, 255, 0);
					strcat(completeKey, buffer);
				}

				// Decode cipher, using completeCipher to store the result since we know
				// it's big enough.
				// Plaintext is created character-by-character. First it converts spaces to [
				// for math purposes. It then uses the OTP conversion process: subtract the
				// key from the cipher, add 27 to get around negatives,
				// mod by 27, then converts to uppercase chars again.
				// Converts [ back into spaces.
				// It leaves the @@ at the end for sending back.
				for (i = 0; i < strlen(completeCipher)-2; i++) {
					if (completeCipher[i] == 32) completeCipher[i] = 91;
					if (completeKey[i] == 32) completeKey[i] = 91;
					completeCipher[i] = ((completeCipher[i]-completeKey[i]+27) % 27) + 65;
					if (completeCipher[i] == 91) completeCipher[i] = 32;
				}

				// Send cipher back, breaking up the complete message to buffer-sized chunks,
				// not stopping until all the data has been written.
				charsWritten = 0;
				do {
					memset(buffer, '\0', sizeof(buffer));
					strncpy(buffer, &completeCipher[charsWritten], sizeof(buffer)-1);
					charsWritten += send(estConnFD, buffer, strlen(buffer), 0);
				} while (charsWritten < strlen(completeCipher));

				// Now that the cipher is sent, connection can be closed and child offers
				// itself up for reaping.
				close(estConnFD);

				exit(0);

			default:	// Parent (listening) process
				pidArr[numChild] = spawnid;
				numChild++;
		

		}
	}
	close(listenSocketFD);
	return 0;	
}
