
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
/*********************************************************************************************************************************************
Tatyana Vlaskin (vlaskint@onid.oregonstate.edu)
CS344 Spring 2015
Program 4
Filename: otp_dec_d.c

References: a lot of code is taken from the lecture notes and from the links included in the code

Description:
otp_dec_d listening_port
Program performs exactly as otp_enc_d, except it will decrypt given cyphertext
Receive ciphertext and key from otp_dec
Perform syntax as otp_enc_d
Return plaintext to otp_dec

Adopted from:references will be provided uppon request

**********************************************************************************************************************************************/


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
    function that will determine the ciphertext size
 ****************************************************************/
int size_Of_Ciphertext(FILE *pointer_to_File);

/**************************************************************
    function to get a key size
 ****************************************************************/
int size_Of_Keytext(FILE *pointer_to_File);

/**************************************************************
    function that will save ciphertext into a string
 ****************************************************************/
void change_Ciphertext_to_String(char *ciphertext_String, int ciphetext_Size, FILE *pointer_to_File);

/**************************************************************
    function that will take key from the file and save it
    into a string
 ****************************************************************/
void change_Keytext_to_String(char *keytext_String, int keytexxt_Size, FILE *pointer_to_File);

/**************************************************************
    function that will get a ciphertext and decrypt it

 ****************************************************************/
void decrypt_ciphertext(char *ciphertext_String, int ciphetext_Size, char *keytext_String, int keytexxt_Size, char *ciphertext);

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
int number_children = 0; //will keep track of children, up to 5 children are allowed
static void wait_for_child(int sig){
	while (waitpid(-1, NULL, WNOHANG) > 0);
	number_children--;
}


int main (int argc, char *argv[]){
    //check and make sure that correct number of arguments was entered
	if (argc < 2){
		printf("valid input of arguments: otp_dec_d port\n");
		exit(1);
	}

	///set up sockets--code is taken from lecture notes
	///and https://github.com/AndriusBil/BattleShip-C/blob/master/simple-server.c
	//http://man7.org/tlpi/code/online/dist/procexec/demo_clone.c.html
	//http://www.martinbroadhurst.com/source/forked-server.c.html
	int sockfd, newsockfd, sin_size, pid;
	struct sockaddr_in addr_local;
	struct sockaddr_in addr_remote;
	int port_Number = atoi(argv[1]);
	struct sigaction sa;

	// Get the socket file descriptor
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1 )	{
		fprintf(stderr, "ERROR: Failed to get Socket Descriptor. (errno = %d)\n", errno);
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
		fprintf(stderr, "ERROR: Failed to listen to  Port. (errno = %d)\n", errno);
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
	// Main loop that accepts and processes client connections --taken from the lecture notes
	while (1){
		sin_size = sizeof(struct sockaddr_in);
		// Wait for any connections from the client
		if ((newsockfd = accept(sockfd, (struct sockaddr *)&addr_remote, &sin_size)) == -1)	{
			fprintf(stderr, "ERROR: Obtaining new socket descriptor. (errno = %d)\n", errno);
			exit(1);
		}
		// Create child process to handle processing multiple connections
		number_children++; // Keep track of number of open children
		pid = fork();
		if (pid < 0){
			perror("ERROR during fork");
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

	// If client is not an allowed client, then reject it
	if (!server_Encountred_Client){
		// Send rejection message
		strncpy(handshake_Reply, "R", 1);
		sent_Response_to_Client(socket, handshake_Reply);
		exit(0); // Exit child process
	}
	//if there are more than 5 server children  connection will be closed
	if (number_children > 5){
		strncpy(handshake_Reply, "T", 1);
		sent_Response_to_Client(socket, handshake_Reply);
		exit(0); // Exiting the child process
	}
	//send repsonse to client
	sent_Response_to_Client(socket, handshake_Reply);
	// Receive the ciphertext and key file from the client as a combined file
	int receiveTemppointer_to_File = file_Descriptor();
	FILE *pointer_to_File = fdopen(receiveTemppointer_to_File, "w+");
	//if file cannot be open display error message
	if (pointer_to_File == 0){
		printf("File temporary receive cannot be opened file on server.\n");
	}
	else{
		receive_File_from_Client(socket, pointer_to_File);
	}
	append_New_Line_to_End_of_File(pointer_to_File);
	// Get the cipher text from the file and save to a string  to decrypt
	int ciphetext_Size = size_Of_Ciphertext(pointer_to_File);
	//allocate memory for string from the file
	char *ciphertext_String = malloc(ciphetext_Size + 1);
	//clear
	bzero(ciphertext_String, ciphetext_Size + 1);
	//chance the ciphertext to string
	change_Ciphertext_to_String(ciphertext_String, ciphetext_Size, pointer_to_File);
	// Get key text from the file and save to a string in order to decrypt it
	int keytexxt_Size = size_Of_Keytext(pointer_to_File);
	// Allocates memory for the string taken from the file
	char *keytext_String = malloc(keytexxt_Size + 1);
	bzero(keytext_String, keytexxt_Size + 1);
	//chance keyxt to string
	change_Keytext_to_String(keytext_String, keytexxt_Size, pointer_to_File);
	// allocate space to encypted string
	char *ciphertext = malloc(ciphetext_Size + 1);
	bzero(ciphertext, ciphetext_Size + 1);
	//decript tht ciphertext
	decrypt_ciphertext(ciphertext_String, ciphetext_Size, keytext_String, keytexxt_Size, ciphertext);
	int resultTempFD = 	file_Descriptor();
	FILE *resultpointer_to_File = fdopen(resultTempFD, "w+");
	if (resultpointer_to_File != 0)	{
		fputs(ciphertext, resultpointer_to_File);
		append_New_Line_to_End_of_File(resultpointer_to_File);
	}
	// Send File to Client
	send_File_to_Client(socket, resultTempFD);
	// Clean up
	free(ciphertext_String);
	free(keytext_String);
	free(ciphertext);
	fclose(pointer_to_File);
	close(receiveTemppointer_to_File);
	close(socket);


}

/**************************************************************
    functon that sends response to the clients handshake

 ****************************************************************/
void sent_Response_to_Client(int socket, char *serverResponse){
	char send_Buffer[2]; // Send buffer
	bzero(send_Buffer, 2);
	strncpy(send_Buffer, serverResponse, 1);
	if (send(socket, send_Buffer, 1, 0) < 0)	{
		printf("[otp_dec_d] ERROR: Failed to send client a response.");
		exit(1);
	}
}

/**************************************************************
    function received initial message from the client
    1 if client is compatible
    0 if client is not compatible
 ****************************************************************/
int received_Handshake_from_Client(int socket){
    //receive buffer
	char receive_Buffer[8];
	//clear a buffer
	bzero(receive_Buffer, 8);
	recv(socket, receive_Buffer, LENGTH, 0);
	//if the client is valid
	if (strcmp(receive_Buffer, "otp_dec") == 0)	{
		return 1;
	}
	//if the client/ correncction is not valid
	else{
		return 0;
	}
}

/**************************************************************
    function that will get a ciphertext and decrypt it

 ****************************************************************/
void decrypt_ciphertext(char *ciphertext_String, int ciphetext_Size, char *keytext_String, int keytexxt_Size, char *ciphertext){
	int i;
	char current_Character_Processing;
	int current_Number_Processing;
	int currCipherTextNumber;
	int current_Keytext_Number;
	for (i = 0; i < ciphetext_Size; i++){
		// Get the number mappings
		currCipherTextNumber = convet_Character_to_Number(ciphertext_String[i]);
		current_Keytext_Number = convet_Character_to_Number(keytext_String[i]);
		// Get the number after encyption
		current_Number_Processing = (currCipherTextNumber - current_Keytext_Number) % NUMBER_ALLOWED_CHARS;
		if (current_Number_Processing < 0){
			current_Number_Processing += NUMBER_ALLOWED_CHARS;
		}
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
	if (number < 0 || 27 < number){
        // Lower case 'e' means that there was an invalid number
		return 'e';
	}
	return possible_Characters[number];
}

/**************************************************************
    function is opposite of the char convert_Number_to_Character(int number)
    this function will map number to the character

 ****************************************************************/
int convet_Character_to_Number(char character){
	static const char possible_Characters[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ ";
	int i;
	for (i = 0; i < NUMBER_ALLOWED_CHARS; i++){
		if (character == possible_Characters[i]){
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
	if (fseek(pointer_to_File, 0, SEEK_SET) == -1){
		printf("Received file pointer reset failed\n");
	}
	// Count the number of characters
	bzero(read_Buffer, LENGTH);
	while (fread(read_Buffer, sizeof(char), LENGTH, pointer_to_File) > 0){
		// Loop through the buffer to count characters
		for (i = 0; i < LENGTH; i++)	{
			// Check if we found the first semicolon
			if (!fits_Semicolon && read_Buffer[i] == ';'){
				fits_Semicolon = 1;
				continue;
			}
			if (fits_Semicolon){
                 // Copy the file contents to the string
				keytext_String[string_Tracker] = read_Buffer[i];
				string_Tracker++;
				file_Tracker++;
			}

			// Exit loop if we reached the end of the key length
			if (file_Tracker == (keytexxt_Size)){
				break;
			}
		}
		bzero(read_Buffer, LENGTH);
	}
}

/**************************************************************
    function that will save ciphertext into a string
 ****************************************************************/
void change_Ciphertext_to_String(char *ciphertext_String, int ciphetext_Size, FILE *pointer_to_File){
	char read_Buffer[LENGTH];
	int i;
	int file_Tracker = 0;
	int string_Tracker = 0;
	// Set file pointer to the start of the file
	if (fseek(pointer_to_File, 0, SEEK_SET) == -1)	{
		printf("Received file pointer reset failed\n");
	}
	// Count the number of characters
	bzero(read_Buffer, LENGTH);
	while (fread(read_Buffer, sizeof(char), LENGTH, pointer_to_File) > 0){
		// Loop through the buffer to count characters
		for (i = 0; i < LENGTH; i++){
			// Exit loop if we reached the end of the cipher text portion of the file
			if (file_Tracker == (ciphetext_Size)){
				break;
			}
			// Copy the file contents to the string
			ciphertext_String[string_Tracker] = read_Buffer[i];
			string_Tracker++;
			file_Tracker++;
		}
		bzero(read_Buffer, LENGTH);
	}
}

/**************************************************************
    function to get a key size
 ****************************************************************/
int size_Of_Keytext(FILE *pointer_to_File){
	char read_Buffer[LENGTH];
	int i;
	int keytexxt_Size = 0;
	int fits_Semicolon = 0;
	int last_Semicolumn = 0;
	// Set file pointer to the start of the file
	if (fseek(pointer_to_File, 0, SEEK_SET) == -1)	{
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
				// Found the file end semicolon. Exit.
				if (read_Buffer[i] == ';'){
					last_Semicolumn = 1;
					break;
				}
				keytexxt_Size++;
			}
		}
		bzero(read_Buffer, LENGTH);

		if (last_Semicolumn)	{
			// Found the last semi-colon, exit out of the loop
			break;
		}
	}

	return keytexxt_Size;
}

/**************************************************************
    function that will determine the ciphertext size
 ****************************************************************/
int size_Of_Ciphertext(FILE *pointer_to_File){
	char read_Buffer[LENGTH];
	int i;
	int file_Size = 0;
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
			// Found the semi-colon delimiter. Break from loop
			if (read_Buffer[i] == ';')	{
				fits_Semicolon = 1;
				break;
			}
			file_Size++; // Keep track of the file size
		}
		bzero(read_Buffer, LENGTH);
		if (fits_Semicolon){
			// Found the delimiter. Break out of the loop
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
	if (temppointer_to_File == 0){
		fprintf(stderr, "ERROR: File temp received not found on server.");
		exit(1);
	}
	bzero(send_Buffer, LENGTH);
	int read_Size;
	while ((read_Size = read(temppointer_to_File, send_Buffer, LENGTH)) > 0){
		if (send(socket, send_Buffer, read_Size, 0) < 0)	{
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
    // Receiver buffer
	char receive_Buffer[LENGTH];
	// Clear out the buffer
	bzero(receive_Buffer, LENGTH);
	// Loop the receiver until all file data is received
	int bytes_Received = 0;
	while ((bytes_Received = recv(socket, receive_Buffer, LENGTH, 0)) > 0){
		int bytes_Written = fwrite(receive_Buffer, sizeof(char), bytes_Received, temppointer_to_File);
		if (bytes_Written < bytes_Received){
			printf("[otp_dec_d] File write failed on server.\n");
		}
		bzero(receive_Buffer, LENGTH);
		if (bytes_Received == 0 || bytes_Received != 512){
			break;
		}
	}
	if (bytes_Received < 0){
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
    function to get temporary file descriptor
 ***************************************************************/
int file_Descriptor(){
	char temp_File_Buffer[32];
	char buffer[24];
	int filedes;
	// clear the buffer
	bzero(temp_File_Buffer, sizeof(temp_File_Buffer));
	bzero(buffer, sizeof(buffer));
	// Set up temp template
	strncpy(temp_File_Buffer, "/tmp/myTmpFile-XXXXXX", 21);
	errno = 0;
	// Create the temporary file by replacing Xs
	filedes = mkstemp(temp_File_Buffer);
	// when a file is closed or the program exits a temporary file is deleted
	unlink(temp_File_Buffer);
	if (filedes < 1)	{
		printf("\n Creation of temporary file failed. Error: [%s]\n", strerror(errno));
		return 1;
	}
	return filedes;
}
/**************************************************************
function to add new line to the end of file
 ****************************************************************/
void append_New_Line_to_End_of_File(FILE *pointer_to_File){
	char newline_Buffer[1] = "\n";
	// Set the file pointer to the end of the file
	if (fseek(pointer_to_File, 0, SEEK_END) == -1)	{
		printf("Received file pointer reset failed\n");
	}
	// Write the newline char to the end of the file
	fwrite(newline_Buffer, sizeof(char), 1, pointer_to_File);

	// Set file pointer to the start of the temp file
	if (fseek(pointer_to_File, 0, SEEK_SET) == -1)
	{
		printf("Received file pointer reset failed\n");
	}
}
