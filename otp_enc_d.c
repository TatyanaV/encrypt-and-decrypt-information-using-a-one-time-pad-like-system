/***********************************************************************************************************************
Tatyana Vlaskin (vlaskint@onid.oregonstate.edu)
CS344 Spring 2015
Program 4
Filename: otp_enc_d.c
References: a lot of code is taken from the lecture notes

Description:
otp_enc_d listening_port
Program performs the actual encoding
Run in brackground as daemon
Listen on particular port for otp_enc
Fork new process for each top_enc connection
Supports up to 5 concurrent socket connections
Receive plaintext & key from otp_enc via the port
Strip newline from plainttext in forked process
Encode plaintext to ciphertext in forked process
Return ciphertext to otp_enc in forked process
Once running, output errors as appropriate, but do not crash or exit program.
Program is killable with -KILL signal.

Adopted from: references will be provided upon request

************************************************************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <signal.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <time.h>

#include <sys/sendfile.h>
#include <sys/stat.h>
#include <fcntl.h>

#define LISTEN_QUEUE 5
#define LENGTH 512
#define NUMBER_ALLOWED_CHARS 27


/**************************************************************
    function getr run the forked process and will handle
    the server processing of the client request
 ****************************************************************/
void process_Connection(int socket);

/**************************************************************
    function to get temporary file descriptor
 ***************************************************************/
int file_Descriptor();

/**************************************************************
    function that will get file from the client and places
    it in a temp file
 ****************************************************************/
void receive_File_from_Client(int socket, FILE *temppointer_to_File);

/**************************************************************
    function that will send contents of the temp file
    to the client
 ****************************************************************/
void send_File_to_Client(int socket, int temppointer_to_File);

/**************************************************************
    function to add new line to the end of file
 ***************************************************************/
void append_New_Line_to_End_of_File(FILE *pointer_to_File);

/**************************************************************
    function to get sizze of plaintext
 ***************************************************************/
int size_of_Plaintext(FILE *pointer_to_File);

/**************************************************************
    function to get a key size
 ****************************************************************/
int size_Of_Keytext(FILE *pointer_to_File);

/**************************************************************
    function to save plaintext as a string
 ****************************************************************/
void plaintext_to_String(char *plaintext_String, int plaintext_Size, FILE *pointer_to_File);

/**************************************************************
    function that will take key from the file and save it
    into a string
 ****************************************************************/
void change_Keytext_to_String(char *keytext_String, int keytexxt_Size, FILE *pointer_to_File);

/**************************************************************
    function to encrypt text
 ****************************************************************/
void encrypt_Text(char *plaintext_String, int plaintext_Size, char *keytext_String, int keytexxt_Size, char *ciphertext);

/**************************************************************
    function is opposite of the char convert_Number_to_Character(int number)
    this function will map number to the character

 ****************************************************************/
int convet_Character_to_Number(char character);

/**************************************************************
    function that will map character to a number [0-27]

 ****************************************************************/
char convert_Number_to_Character(int number);

/**************************************************************
    function received initial message from the client
    1 if client is compatible
    0 if client is not compatible
 ****************************************************************/
int received_Handshake_from_Client(int socket);

/**************************************************************
    functon that sends response to the clients handshake

 ****************************************************************/
void sent_Response_to_Client(int socket, char *serverResponse);

// Signal handler to clean up zombie processes
int number_children = 0;
static void wait_for_child(int sig)
{
	while (waitpid(-1, NULL, WNOHANG) > 0);
	number_children--;
}


int main (int argc, char *argv[]){
	if (argc < 2){
		printf("usage: otp_enc_d port\n");
		exit(1);
	}

	//set up socket connection--- copy and past from lecture notes
	int sockfd, newsockfd, sin_size, pid;
	struct sockaddr_in addr_local; // client addr
	struct sockaddr_in addr_remote; // server addr
	int port_Number = atoi(argv[1]);
	struct sigaction sa;

	// Get the socket file descriptor
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1 )	{
		fprintf(stderr, "ERROR: Failed to obtain Socket Descriptor. (errno = %d)\n", errno);
		exit(1);
	}
	// Fill the client socket address struct
	addr_local.sin_family = AF_INET; // Protocol Family
	addr_local.sin_port = htons(port_Number); // Port number
	addr_local.sin_addr.s_addr = INADDR_ANY; // AutoFill local address
	bzero(&(addr_local.sin_zero), 8); // Flush the rest of struct

	// Bind a port
	if ( bind(sockfd, (struct sockaddr*)&addr_local, sizeof(struct sockaddr)) == -1 ){
		exit(1);
	}
	// Set socket option to reuse socket addresses
	int optval = 1;
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

	// Listen to port
	if (listen(sockfd, LISTEN_QUEUE) == -1)	{
		fprintf(stderr, "ERROR: Failed to listen Port. (errno = %d)\n", errno);
		exit(1);
	}
	// Set up the signal handler to clean up zombie children
	sa.sa_handler = wait_for_child;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		perror("sigaction");
		return 1;
	}
	//  loop that accepts and processes client connections
	while (1){
		sin_size = sizeof(struct sockaddr_in);

		// Wait for any connections from the client
		if ((newsockfd = accept(sockfd, (struct sockaddr *)&addr_remote, &sin_size)) == -1)	{
			fprintf(stderr, "ERROR: Obtaining new socket descriptor. (errno = %d)\n", errno);
			exit(1);
		}
		// Create child process for  multiple connections
		//keeping track of number of children
		number_children++;
		pid = fork();
		if (pid < 0){
			perror("ERROR during forking");
			exit(1);
		}
		if (pid == 0){
			// This is the client process
			close(sockfd);
			process_Connection(newsockfd);
			exit(0);
		}
		else{
			close(newsockfd);
		}
	}
}

/**************************************************************
    function getr run the forked process and will handle
    the server processing of the client request

 ****************************************************************/
void process_Connection(int socket){
	char handshake_Reply[2];
	int server_Encountred_Client = received_Handshake_from_Client(socket);
	// If client is not the correct client, then reject it.
	if (!server_Encountred_Client){
		// Send rejection message
		strncpy(handshake_Reply, "R", 1);
		sent_Response_to_Client(socket, handshake_Reply);
		exit(0); // Exiting the child process.
	}

	// If there are more than 5 server children then close the connection
	// with the client
	if (number_children > 5){
		strncpy(handshake_Reply, "T", 1);
		sent_Response_to_Client(socket, handshake_Reply);
		exit(0); // Exiting the child process.
	}
	// Send connection successful back to the client
	strncpy(handshake_Reply, "S", 1);
	sent_Response_to_Client(socket, handshake_Reply);

	// Receive the plaintext and key file from the client
	// Both plaintext and key are in one file
	int receiveTemppointer_to_File = file_Descriptor();
	FILE *pointer_to_File = fdopen(receiveTemppointer_to_File, "w+");
	if (pointer_to_File == 0){
		printf("File temp receive cannot be opened file on server.\n");
	}
	else{
		receive_File_from_Client(socket, pointer_to_File);
	}
	append_New_Line_to_End_of_File(pointer_to_File);
	// Get the plain text from the file and save to a string so we can encrypt it later
	int plaintext_Size = size_of_Plaintext(pointer_to_File);
	char *plaintext_String = malloc(plaintext_Size + 1); // Allocates memory for the string taken from the file
	bzero(plaintext_String, plaintext_Size + 1);
	plaintext_to_String(plaintext_String, plaintext_Size, pointer_to_File);
	// Get the plain text from the file and save to a string so we can encrypt it later
	int keytexxt_Size = size_Of_Keytext(pointer_to_File);
	char *keytext_String = malloc(keytexxt_Size + 1); // Allocates memory for the string taken from the file
	bzero(keytext_String, keytexxt_Size + 1);
	change_Keytext_to_String(keytext_String, keytexxt_Size, pointer_to_File);
	// calculate size of the encypted text so we can allocate space for it.
	char *ciphertext = malloc(plaintext_Size + 1); // Allocates memory for the ciphertext
	bzero(ciphertext, plaintext_Size + 1);
	encrypt_Text(plaintext_String, plaintext_Size, keytext_String, keytexxt_Size, ciphertext);
	int resultTempFD = 	file_Descriptor();
	FILE *resultpointer_to_File = fdopen(resultTempFD, "w+");
	if (resultpointer_to_File != 0)	{
		// printf("putting to file: %s\n", ciphertext); // For debugging only
		fputs(ciphertext, resultpointer_to_File);
		append_New_Line_to_End_of_File(resultpointer_to_File);
	}
	// Send File to Client
	// send_File_to_Client(socket, receiveTemppointer_to_File);
	send_File_to_Client(socket, resultTempFD);
	free(plaintext_String);
	free(keytext_String);
	free(ciphertext);
	fclose(pointer_to_File);
	close(receiveTemppointer_to_File);
	close(socket);
}

/**************************************************************
    function to send response to clients initial handshake
 ****************************************************************/
void sent_Response_to_Client(int socket, char *serverResponse){
	char send_Buffer[2]; // Send buffer
	bzero(send_Buffer, 2);
	strncpy(send_Buffer, serverResponse, 1);
	if (send(socket, send_Buffer, 1, 0) < 0)	{
		printf("[otp_enc_d] ERROR: Failed to send client the handshake response.");
		exit(1);
	}
}

/**************************************************************
    function receives initial message from client
 ****************************************************************/
int received_Handshake_from_Client(int socket){
	char receive_Buffer[8]; // Receiver buffer
	bzero(receive_Buffer, 8); // Clear out the buffer
	recv(socket, receive_Buffer, LENGTH, 0);
	if (strcmp(receive_Buffer, "otp_enc") == 0){
		return 1; // Connection valid
	}
	else{
		return 0; // Received handshake from invalid client
	}
}

/**************************************************************
    function to make ciphertext from plaintext and key
 ****************************************************************/
void encrypt_Text(char *plaintext_String, int plaintext_Size, char *keytext_String, int keytexxt_Size, char *ciphertext){
	int i;
	char current_Character_Processing;
	int current_Number_Processing;
	int current_Plaintext_Number;
	int current_Keytext_Number;
	for (i = 0; i < plaintext_Size; i++)	{
		// Get the number mappings
		current_Plaintext_Number = convet_Character_to_Number(plaintext_String[i]);
		current_Keytext_Number = convet_Character_to_Number(keytext_String[i]);
		// Get the number after encyption
		current_Number_Processing = (current_Plaintext_Number + current_Keytext_Number) % NUMBER_ALLOWED_CHARS;
		// Get the character from the encryption number
		current_Character_Processing = convert_Number_to_Character(current_Number_Processing);
		ciphertext[i] = current_Character_Processing;
	}
}
/**************************************************************
    function that will map character to a number [0-27]

 ****************************************************************/
char convert_Number_to_Character(int number){
	static const char possible_Characters[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ ";

	// Return if the number is out of bounds
	if (number < 0 || 27 < number)	{
		// Lower case 'e' means that there was an invalid number
		return 'e';
	}
	return possible_Characters[number];
}
/**************************************************************
    function is opposite of the char convert_Number_to_Character(int number)
    this function will map number to the character

 ****************************************************************/
int convet_Character_to_Number(char character)
{
	static const char possible_Characters[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ ";
	int i;
	for (i = 0; i < NUMBER_ALLOWED_CHARS; i++)	{
		if (character == possible_Characters[i])		{
			return i;
		}
	}

	return -1;
}

/**************************************************************
    function that will take key from the file and save it
    into a string
 ****************************************************************/
void change_Keytext_to_String(char *keytext_String, int keytexxt_Size, FILE *pointer_to_File){
	char read_Buffer[LENGTH];
	int i;
	int file_Tracker = 0;
	int string_Tracker = 0;
	int fits_Semicolon = 0;
	// Set file pointer to the start of the file
	if (fseek(pointer_to_File, 0, SEEK_SET) == -1)	{
		printf("Received file pointer reset failed\n");
	}
	// Count the number of characters
	bzero(read_Buffer, LENGTH);
	while (fread(read_Buffer, sizeof(char), LENGTH, pointer_to_File) > 0){
		// Loop through the buffer to count characters
		for (i = 0; i < LENGTH; i++){
			// Check if we found the first semicolon
			if (!fits_Semicolon && read_Buffer[i] == ';'){
				fits_Semicolon = 1;
				continue;
			}

			if (fits_Semicolon)	{
                // Copy the file contents to the string
				keytext_String[string_Tracker] = read_Buffer[i];
				string_Tracker++;
				file_Tracker++;
			}
			// Exit loop if we reached the end of the key length
			if (file_Tracker == (keytexxt_Size))	{
				break;
			}

		}
		bzero(read_Buffer, LENGTH);
	}
}

/**************************************************************
    function that will save palintext into a string
 ****************************************************************/
void plaintext_to_String(char *plaintext_String, int plaintext_Size, FILE *pointer_to_File){
	char read_Buffer[LENGTH];
	int i;
	int file_Tracker = 0;
	int string_Tracker = 0;
	// Set file pointer to the start of the file
	if (fseek(pointer_to_File, 0, SEEK_SET) == -1)	{
		printf("Received file pointer failed\n");
	}
	// Count the number of characters
	bzero(read_Buffer, LENGTH);
	while (fread(read_Buffer, sizeof(char), LENGTH, pointer_to_File) > 0){
		// Loop through the buffer to count characters
		for (i = 0; i < LENGTH; i++){
			// Exit loop if we reached the end of the plain text portion of the file
			if (file_Tracker == (plaintext_Size)){
				break;
			}
            // Copy the file contents to the string
			plaintext_String[string_Tracker] = read_Buffer[i];
			string_Tracker++;
			file_Tracker++;
		}
		bzero(read_Buffer, LENGTH);
	}
}

/**************************************************************
    function to get a key size
 ****************************************************************/
int size_Of_Keytext(FILE *pointer_to_File)
{
	char read_Buffer[LENGTH];
	int i;
	int keytexxt_Size = 0;
	int fits_Semicolon = 0;
	int last_Semicolumn = 0;
	// Set file pointer to the start of the file
	if (fseek(pointer_to_File, 0, SEEK_SET) == -1){
		printf("Received file pointer reset failed\n");
	}
	// Count the number of characters
	bzero(read_Buffer, LENGTH);
	while (fread(read_Buffer, sizeof(char), LENGTH, pointer_to_File) > 0){
		// Loop through the buffer to count characters
		for (i = 0; i < LENGTH; i++){
			// Found the first semi-colon delimiter.
			if ((fits_Semicolon == 0) && read_Buffer[i] == ';')	{
				fits_Semicolon = 1;
				continue;
			}
			// Count the characters after the first semi-colon
			if (fits_Semicolon)	{
				// Found the file end semicolon, exit
				if (read_Buffer[i] == ';'){
					last_Semicolumn = 1;
					break;
				}
				keytexxt_Size++;
			}
		}
		bzero(read_Buffer, LENGTH);

		if (last_Semicolumn){
			break;
		}
	}

	return keytexxt_Size;
}

/**************************************************************
    function that will determine the plain size
 ****************************************************************/
int size_of_Plaintext(FILE *pointer_to_File){
	char read_Buffer[LENGTH];
	int i;
	int file_Size = 0;
	int fits_Semicolon = 0;
	// Set file pointer to the start of the file
	if (fseek(pointer_to_File, 0, SEEK_SET) == -1){
		printf("Received file pointer reset failed\n");
	}
	// Count the number of characters
	bzero(read_Buffer, LENGTH);
	while (fread(read_Buffer, sizeof(char), LENGTH, pointer_to_File) > 0){
		// Loop through the buffer to count characters
		for (i = 0; i < LENGTH; i++){
			// Found the semi-colon delimiter. Break from loop
			if (read_Buffer[i] == ';')	{
				fits_Semicolon = 1;
				break;
			}

			file_Size++; // Keep track of the file size
		}
		bzero(read_Buffer, LENGTH);
		if (fits_Semicolon)	{
			// Found the delimiter, break
			break;
		}
	}
	return file_Size;
}

/**************************************************************
    function that will send contents of the temp file
    to the client
 ****************************************************************/
void send_File_to_Client(int socket, int temppointer_to_File){
	char send_Buffer[LENGTH]; // Send buffer
	if (temppointer_to_File == 0)	{
		fprintf(stderr, "ERROR: File temp received not found on server.");
		exit(1);
	}
	bzero(send_Buffer, LENGTH);
	int readSize;
	while ((readSize = read(temppointer_to_File, send_Buffer, LENGTH)) > 0)	{
		if (send(socket, send_Buffer, readSize, 0) < 0)	{
			fprintf(stderr, "ERROR: Failed to send file temp received.");
			exit(1);
		}
		bzero(send_Buffer, LENGTH);
	}
}

/**************************************************************
    function that will get file from the client and places
    it in a temp file
 ****************************************************************/
void receive_File_from_Client(int socket, FILE *temppointer_to_File){
	char receive_Buffer[LENGTH]; // Receiver buffer
	bzero(receive_Buffer, LENGTH); // Clear out the buffer
	// Loop the receiver until all file data is received
	int bytes_Received = 0;
	while ((bytes_Received = recv(socket, receive_Buffer, LENGTH, 0)) > 0)	{
		int bytes_Written = fwrite(receive_Buffer, sizeof(char), bytes_Received, temppointer_to_File);
		if (bytes_Written < bytes_Received)	{
			printf("[otp_enc_d] File write failed on server.\n");
		}
		bzero(receive_Buffer, LENGTH);
		if (bytes_Received == 0 || bytes_Received != 512){
			break;
		}
	}
	if (bytes_Received < 0)	{
		if (errno == EAGAIN){
			printf("recv() timed out.\n");
		}
		else{
			fprintf(stderr, "recv() failed due to errno = %d\n", errno);
			exit(1);
		}
	}
}

/**************************************************************
    function to get a temp file descriptor
 ****************************************************************/
int file_Descriptor(){
	char temp_File_Buffer[32];
	char buffer[24];
	int filedes;
	// clear out the buffers
	bzero(temp_File_Buffer, sizeof(temp_File_Buffer));
	bzero(buffer, sizeof(buffer));
	// Set up temp template
	strncpy(temp_File_Buffer, "/tmp/myTmpFile-XXXXXX", 21);
	errno = 0;
	// Create the temporary file, this function will replace the 'X's
	filedes = mkstemp(temp_File_Buffer);
	// Call unlink so that whenever the file is closed or the program exits
	// the temporary file is deleted
	unlink(temp_File_Buffer);

	if (filedes < 1){
		printf("\n Creation of temp file failed with error [%s]\n", strerror(errno));
		return 1;
	}
	return filedes;
}

/**************************************************************
function to add new line to the end of file
****************************************************************/
void append_New_Line_to_End_of_File(FILE *pointer_to_File)
{
	char newline_Buffer[1] = "\n";
	// Set the file pointer to the end of the file
	if (fseek(pointer_to_File, 0, SEEK_END) == -1){
		printf("Received file pointer reset failed\n");
	}
	// Write the newline char to the end of the file
	fwrite(newline_Buffer, sizeof(char), 1, pointer_to_File);
	// Set file pointer to the start of the temp file
	if (fseek(pointer_to_File, 0, SEEK_SET) == -1)	{
		printf("Received file pointer reset failed\n");
	}
}
