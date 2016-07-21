/***********************************************************************************************************************************
Tatyana Vlaskin (vlaskint@onid.oregonstate.edu)
CS344 Spring 2015
Program 4
Filename: otp_enc.c
Description:
otp_enc plainstext key port
Program connects to otp_enc_d and asked it to perform a one-time pad style encryption
Runnable in three ways (see instructions for details)
Connect to otp_enc_d with the given port
If given port not found in otp_enc_d, report error and port # and exit(2)
Should not be able to connect to otp_dec_d, even with correct port
Send plaintext and key to otp_enc_d
Receive ciphertext from otp_enc_d
Output to stdout or save to file with newline added
If ciphertext has bad characters or invalid length, exit(1) with error message
If program ran successfully, exit(0)

Adopted from:
https://github.com/hinesro/cs344/tree/master/assignment4
https://github.com/fedackb/cs344-program4/tree/master/src
https://github.com/chadg1980/code
//github.com/atulag/CS425-Assignments/blob/98084d32b1766fc4394a191dfcb7ea8f6f2ea30e/ass1/client.c
https://github.com/sorki/state-server/blob/91280134d3e6118ebbbe96187a1a44d5a8f6a6a0/examples/c/state.c
https://github.com/softghost/VM-placement/blob/40008fa7c2b0df5e984f7b1757d1e025c895209c/tester.c
other references:
//http://en.wikipedia.org/wiki/Umask
//http://www.tutorialspoint.com/unix_sockets/socket_server_example.htm
//http://man7.org/tlpi/code/online/dist/daemons/become_daemon.c.html
//https://www.youtube.com/watch?v=zWqLYby99EU
//http://pubs.vmware.com/vsphere-60/index.jsp?topic=%2Fcom.vmware.vmci.pg.doc%2FvsockAppendix.8.3.html
//http://courses.cs.washington.edu/courses/cse476/02wi/labs/lab1/client.c
//http://www.cs.rpi.edu/~moorthy/Courses/os98/Pgms/socket.html
//http://www.csd.uoc.gr/~hy556/material/tutorials/cs556-3rd-tutorial.pdf
//http://www.cs.bham.ac.uk/~exr/lectures/opsys/12_13/examples/sockets/server.c
//http://man7.org/linux/man-pages/man3/malloc.3.html
http://www.linuxhowtos.org/C_C++/socket.htm
https://github.com/rocko-rocko/Application-Layer-File-Transfer-Protocol/blob/master/cli/client.c
https://github.com/najlepsiwebdesigner/cpp-file-sockets/blob/master/client.cpp
http://unixjunkie.blogspot.com/2006/08/apue2e-acknowledgement.html
http://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=5&ved=0CDAQFjAEahUKEwi_4O--moLGAhWFYK0KHaWpAIc&url=http%3A%2F%2Fideone.com%2Fplain%2FCPsttI&ei=kaV2Vf_TEIXBtQWl04K4CA&usg=AFQjCNF3pWJdpEv0nf5jWemmVJCWZj3lSg
http://newscentral.exsees.com/item/b39d0169da6080e3af909d7fa568c47f-a9122af86c09539e315639660b728725
http://www.linuxquestions.org/questions/showthread.php?p=4714903
http://question.ikende.com/question/2D31353131313731373336
http://w3facility.org/question/c-send-file-and-text-via-socket/
http://question.ikende.com/question/2D3933333938333138
http://newscentral.exsees.com/item/257ef2eff3db48163349b9100f4285d8-18ed4375dd96bc0e6108a97587399113
https://github.com/mohan43u/simple-tcp/blob/master/functions.c
http://man7.org/linux/man-pages/man3/errno.3.html
http://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=2&ved=0CCUQFjABahUKEwi_hI-EoILGAhUIT5IKHW3uALs&url=http%3A%2F%2Fweb.mit.edu%2Ffreebsd%2Fhead%2Fcontrib%2Flibarchive%2Flibarchive%2Farchive_read_disk_entry_from_file.c&ei=YKt2Vb_UKIieyQTt3IPYCw&usg=AFQjCNEfAuaBpliWrNTRzQFmZr4eU_NVOA&bvm=bv.95039771,d.aWw
http://sourcecodebrowser.com/lprng/3.8.A/accounting_8c.html
http://fossies.org/linux/ifhp/src/ifhp.c
http://lxr.mein.io/source/luci2-ui/luci2/src/io/main.c
http://www.thegeekstuff.com/2012/06/c-temporary-files/
http://stackoverflow.com/questions/21517952/creating-temporary-file-from-c-program-in-linux-mint
http://4byte.cn/question/77892/creating-temporary-file-from-c-program-in-linux-mint.html
https://code.google.com/p/fideo/source/browse/fideo/RNABackendProxy.h?r=be319b54ea60dc5b845cb803f324a83c400cc80a
http://man7.org/tlpi/code/online/dist/procexec/demo_clone.c.html
//and https://github.com/AndriusBil/BattleShip-C/blob/master/simple-server.c
//http://www.martinbroadhurst.com/source/forked-server.c.html


************************************************************************************************************************************/
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
#define LENGTH 512

/**************************************************************
    function to display error message
 * ***************************************************************/
void error(const char *message);

/**************************************************************
    Function to connect and communicate to the server
    function taken from the lecture notes and
    http://www.linuxhowtos.org/C_C++/socket.htm
    https://github.com/rocko-rocko/Application-Layer-File-Transfer-Protocol/blob/master/cli/client.c
    https://github.com/najlepsiwebdesigner/cpp-file-sockets/blob/master/client.cpp
    http://unixjunkie.blogspot.com/2006/08/apue2e-acknowledgement.html
    http://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=5&ved=0CDAQFjAEahUKEwi_4O--moLGAhWFYK0KHaWpAIc&url=http%3A%2F%2Fideone.com%2Fplain%2FCPsttI&ei=kaV2Vf_TEIXBtQWl04K4CA&usg=AFQjCNF3pWJdpEv0nf5jWemmVJCWZj3lSg
    http://newscentral.exsees.com/item/b39d0169da6080e3af909d7fa568c47f-a9122af86c09539e315639660b728725
    http://www.linuxquestions.org/questions/showthread.php?p=4714903
    http://question.ikende.com/question/2D31353131313731373336
    http://w3facility.org/question/c-send-file-and-text-via-socket/
    http://question.ikende.com/question/2D3933333938333138
    http://newscentral.exsees.com/item/257ef2eff3db48163349b9100f4285d8-18ed4375dd96bc0e6108a97587399113

 *****************************************************************/
void connect_To_Server (char *port_String, char *plaintext_Name, char *key_File);

/**************************************************************
    function that will remove the new line character at the
    end of the string and add null character
 ****************************************************************/
void swap_New_Line_With_Null_Character(char *file_Name);

/**************************************************************
    function to check to length of they key
 ****************************************************************/
void validate_Key_Length(long key_Size, long plaintext_Size, char *key_Name);

/**************************************************************
    function to check for invalid characters
 ****************************************************************/
void invaid_Characters(char *string_thant_Needs_Checking, int string_Lenght);

/**************************************************************
    function to send tem file to the socket
 * ***************************************************************/
void send_File_to_Server(int sockfd, int temporaroty_File);

/**************************************************************
    function to receive a ciphertext file from the server
    and display it on the screen
 ****************************************************************/
void receive_File_from_Server(int sockfd);

/**************************************************************
    function to combine contents of 2 files into one file
 *****************************************************************/
int meerge_Two_Files(char *file1_Name, char *file2_Name);

/**************************************************************
    function to get temporary file descriptor
 ***************************************************************/
int file_Descriptor();

/**************************************************************
    function to remove new line in the buffer and add semicolon
 ****************************************************************/
void remove_New_Line_from_Buffer(char *buffer, int buffer_Size);

/**************************************************************
    function to add a newline to the end of the file
****************************************************************/
void validate_the_End_of_File(char *file_Name);

/**************************************************************
    function to send a clients infromation to the server
 ****************************************************************/
void request_Handshake_from_Server(int sockfd);

/**************************************************************
    function to receive a handshake from the server
 ****************************************************************/
void responses_From_Server_to_Handshake(int sockfd, char *response_to_Handshake);

int main(int argc, char *argv[])
{
	// If the user did not enter the correct number of parameters,
	//  display the correct message.
	if (argc != 4)
	{
		printf("usage: otp_enc plaintext key port\n");
		exit(1);
	}
    ///we get the plaintext
    ///1. get the size of the plaintext
    ///2.compare the size of the plaintext to the size of the key
    ///3. save the plaintext into the string
    ///4. check the plaintext from illigal charactes
    ///5. send the plaintext to the server
    //http://stackoverflow.com/questions/28239081/reading-in-a-binary-file-in-c-then-matching-data-from-the-file-to-what-i-have-r
	FILE *pointer_to_File = fopen(argv[1], "rb");
	if (pointer_to_File == 0){
		printf("Plaintext file does not exist\n");
		exit(1);
	}
    // Find the size of the file
	//http://beej.us/guide/bgc/output/html/multipage/fseek.html
	//find the end of the file
	fseek(pointer_to_File, 0, SEEK_END);
	//find the size
	long plaintext_Size = ftell(pointer_to_File);
	//find the begining of the file
	fseek(pointer_to_File, 0, SEEK_SET);
	//allocate memory for the string
	char *plaintext_String = malloc(plaintext_Size + 1);
	//get a string from a file
	fread(plaintext_String, plaintext_Size, 1, pointer_to_File);
	//close file
	fclose(pointer_to_File);
	//add a null terminator to the string
	plaintext_String[plaintext_Size] = 0;
	//check for the new line is exist swap it with null character
	swap_New_Line_With_Null_Character(plaintext_String);

	///GET THE KEY
	///1. get the size of the key
	///2.compare the size of the key to the size of the ciphertext
	///3.save the key  as a string
	///4. analyze a key string for invalid character
	// Check if the file exists
	pointer_to_File = fopen(argv[2], "rb");
	if (pointer_to_File == 0){
		printf("key file does not exist\n");
		exit(1);
	}
	// Find the size of the file
	//find the end of the file
	fseek(pointer_to_File, 0, SEEK_END);
	//find the size of the file
	long key_Size = ftell(pointer_to_File);
	//find the begining of the file
	fseek(pointer_to_File, 0, SEEK_SET);
    //allocate memory for the string
	char *key_String = malloc(key_Size + 1);
	//get a string from the file
	fread(key_String, key_Size, 1, pointer_to_File);
	//close file
	fclose(pointer_to_File);
	//add a null teminator to the sting
	key_String[key_Size] = 0;
	//if nesessary swap new line with the null terminator at the end of the string
	swap_New_Line_With_Null_Character(key_String);
	//validate the size of the keytest and plaintext stings
	validate_Key_Length(key_Size, plaintext_Size, argv[2]);
	// Check for invalid characters
	invaid_Characters(plaintext_String, plaintext_Size);
	invaid_Characters(key_String, key_Size);
	// Connect to server to send the plaintext and key and get a response from the server
	connect_To_Server (argv[3], argv[1], argv[2]);
	// Free the strings
	free(plaintext_String);
	free(key_String);

	return 0;
}

/**************************************************************
    Function to connect and communicate to the server
    function taken from the lecture notes and
    http://www.linuxhowtos.org/C_C++/socket.htm
    https://github.com/rocko-rocko/Application-Layer-File-Transfer-Protocol/blob/master/cli/client.c
    https://github.com/najlepsiwebdesigner/cpp-file-sockets/blob/master/client.cpp
    http://unixjunkie.blogspot.com/2006/08/apue2e-acknowledgement.html
    http://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=5&ved=0CDAQFjAEahUKEwi_4O--moLGAhWFYK0KHaWpAIc&url=http%3A%2F%2Fideone.com%2Fplain%2FCPsttI&ei=kaV2Vf_TEIXBtQWl04K4CA&usg=AFQjCNF3pWJdpEv0nf5jWemmVJCWZj3lSg
    http://newscentral.exsees.com/item/b39d0169da6080e3af909d7fa568c47f-a9122af86c09539e315639660b728725
    http://www.linuxquestions.org/questions/showthread.php?p=4714903
    http://question.ikende.com/question/2D31353131313731373336
    http://w3facility.org/question/c-send-file-and-text-via-socket/
    http://question.ikende.com/question/2D3933333938333138
    http://newscentral.exsees.com/item/257ef2eff3db48163349b9100f4285d8-18ed4375dd96bc0e6108a97587399113


 *****************************************************************/
void connect_To_Server(char *port_String, char *ciphertext_File, char *key_File){
	int sockfd;
	struct sockaddr_in remote_addr;
	int port_Number = atoi(port_String);
	char response_to_Handshake[2];
	bzero(response_to_Handshake, 2);
    // Get the Socket file descriptor
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)	{
		printf("Error: Failed to obtain socket descriptor.\n");
		exit(2);
	}
	// Fill the socket address struct
	remote_addr.sin_family = AF_INET;
	remote_addr.sin_port = htons(port_Number);
	inet_pton(AF_INET, "127.0.0.1", &remote_addr.sin_addr);
	bzero(&(remote_addr.sin_zero), 8);
	// Try to connect the remote
	if (connect(sockfd, (struct sockaddr *)&remote_addr, sizeof(struct sockaddr)) == -1){
		printf("Error: could not contact otp_dec_d on port %s\n", port_String);
		exit(2);
	}
	// Send initial handshake message with the combined file to the server
	request_Handshake_from_Server(sockfd);
    //response from the server
	responses_From_Server_to_Handshake(sockfd, response_to_Handshake);

	if (strcmp(response_to_Handshake, "R") == 0){
		// Server rejected this client because this client is unautherized to connect
		fprintf(stderr, "Error: could not contact otp_dec_d on port %s\n", port_String);
		exit(1);
	}
	else if (strcmp(response_to_Handshake, "T") == 0)	{
		// Server is busy
		printf("Error: Server rejected the client due to lack of space\n");
		exit(1);
	}
    //validating that ciphetextfile and keyfile have null character at the end
	validate_the_End_of_File(ciphertext_File);
	validate_the_End_of_File(key_File);
    //merger the key and ciphertext to send to the server
 	int resultTempFd = meerge_Two_Files(ciphertext_File, key_File);
    //send combined file
	send_File_to_Server(sockfd, resultTempFd);
	// Receive result file from server
	receive_File_from_Server(sockfd);
	close (sockfd);
}

/**************************************************************
    function to receive a handshake from the server
 ****************************************************************/
void responses_From_Server_to_Handshake(int sockfd, char *response_to_Handshake){
	char received_Buffer[2];
	//clear the buffer
	bzero(received_Buffer, 2);
	// Wait for information from the server
	recv(sockfd, received_Buffer, 1, 0);
    //copy response from the buffer to the char sting
	strncpy(response_to_Handshake, received_Buffer, 1);
}
/**************************************************************
    function to send a clients infromation to the server
 ****************************************************************/
void request_Handshake_from_Server(int sockfd){
	char send_Buffer[LENGTH];
	//clear the buffer
	bzero(send_Buffer, LENGTH);
	strncpy(send_Buffer, "otp_dec", LENGTH);
	int size_of_File_tobe_Send = 7;
	if (send(sockfd, send_Buffer, size_of_File_tobe_Send, 0) < 0){
		printf("[otp_dec] Error: Failed to send handshake.\n");
	}
}
/**************************************************************
    function to add a newline to the end of the file
* ***************************************************************/
void validate_the_End_of_File(char *file_Name){
	char read_Buffer[LENGTH];
	int i;
	int foundNewLineChar = 0;
	FILE *pointer_to_File = fopen(file_Name, "rb+");
    //clear the buffer
	bzero(read_Buffer, LENGTH);
	while (fread(read_Buffer, sizeof(char), LENGTH, pointer_to_File) > 0)	{
		// Loop through the buffer to look for the newline
		for (i = 0; i < LENGTH; i++){
			//if new line is found, we can exit the file
			if (read_Buffer[i] == '\n'){
				foundNewLineChar = 1;
				break;
			}
			//if we are at the end of the file we can exit the loop
			if (read_Buffer[i] == '\0'){
				break;
			}
		}
		bzero(read_Buffer, LENGTH);
	}
	if (!foundNewLineChar){
		//if new line is not found, addend it
		char newLineChar[1] = "\n";
		fwrite (newLineChar, sizeof(char), sizeof(newLineChar), pointer_to_File);
	}
	fclose(pointer_to_File);
}

/**************************************************************
    function to receive a ciphertext file from the server
    and display it on the screen
 ****************************************************************/
void receive_File_from_Server(int sockfd){
	char received_Buffer[LENGTH];
	bzero(received_Buffer, LENGTH);
	// Wait for info that is sent from server
	int receiveSize = 0;
	while ((receiveSize = recv(sockfd, received_Buffer, LENGTH, 0)) > 0)	{
		// Output the decryption results
		printf("%s", received_Buffer);
		bzero(received_Buffer, LENGTH);
		// Exit out of receive loop if data size is invalid
		if (receiveSize == 0 || receiveSize != 512)	{
			break;
		}
	}
	if (receiveSize < 0){
        //http://man7.org/linux/man-pages/man3/errno.3.html
		if (errno == EAGAIN){
			printf("[otp_dec] recv() timed out.\n");
		}
		else{
			printf("[otp_dec] recv() failed \n");
		}
	}
}

/**************************************************************
    function to send tem file to the socket
 * ***************************************************************/
void send_File_to_Server(int sockfd, int temporaroty_File){
	char send_Buffer[LENGTH];
	bzero(send_Buffer, LENGTH);
	int size_of_File_tobe_Send;
	while ((size_of_File_tobe_Send = read(temporaroty_File, send_Buffer, sizeof(send_Buffer))) > 0)	{
		if (send(sockfd, send_Buffer, size_of_File_tobe_Send, 0) < 0){
			printf("[otp_dec] Error: Failed to send file.\n");
			break;
		}
		bzero(send_Buffer, LENGTH);
	}
}
/**************************************************************
    function to combine contents of 2 files into one file
 *****************************************************************/
int meerge_Two_Files(char *file1_Name, char *file2_Name){
	char read_Buffer[LENGTH];
	int size_of_File_tobe_Read = 0;
	FILE *file1_Pointer = fopen(file1_Name, "rb");
	FILE *file2_Pointer = fopen(file2_Name, "rb");
	int temporary_File = file_Descriptor();
	// Add the contents of the first file to the temp file.
	bzero(read_Buffer, LENGTH);
	while ((size_of_File_tobe_Read = fread(read_Buffer, sizeof(char), LENGTH, file1_Pointer)) > 0){
        //remove new line and add null character
		remove_New_Line_from_Buffer(read_Buffer, LENGTH);
        //write to temp file
		if (write(temporary_File, read_Buffer, size_of_File_tobe_Read) == -1){
			printf("[otp_dec] Error in combining ciphertext and key\n");
		}
		bzero(read_Buffer, LENGTH);
	}
	// Add the contents of the second file to the temp file
	bzero(read_Buffer, LENGTH);
	while ((size_of_File_tobe_Read = fread(read_Buffer, sizeof(char), LENGTH, file2_Pointer)) > 0){
        //remove new line and add null character
		remove_New_Line_from_Buffer(read_Buffer, LENGTH);
        //write to temp file
		if (write(temporary_File, read_Buffer, size_of_File_tobe_Read) == -1) 	{
			printf("[otp_dec] Error during merge of ciphertext and key\n");
		}
		bzero(read_Buffer, LENGTH);
	}
	// Reset  file pointer for temp file
	if (-1 == lseek(temporary_File, 0, SEEK_SET)){
		printf("File pointer reset for combined file failed\n");
	}
    //close file pointer
    fclose(file1_Pointer);
	fclose(file2_Pointer);

	return temporary_File;
}

/**************************************************************
    function to display error message
 * ***************************************************************/
void error(const char *message){
	perror(message);
	exit(1);
}

/**************************************************************
    function that will remove the new line character at the
    end of the string and add null character
 ****************************************************************/
void swap_New_Line_With_Null_Character(char *string_tobe_Modified){
	size_t ln = strlen(string_tobe_Modified) - 1;
	if (string_tobe_Modified[ln] == '\n'){
		string_tobe_Modified[ln] = '\0';
	}
}

/**************************************************************
    function to check to length of they key
 ****************************************************************/
void validate_Key_Length(long key_Size, long ciphetext_Size, char *key_Name){
	if (key_Size < ciphetext_Size){
		printf("Error: key %s is too short\n", key_Name);
		exit(1);
	}
}

/**************************************************************
    function to check for invalid characters
 ****************************************************************/
void invaid_Characters(char *string_tobe_Modified, int string_Lenght){
	static const char possible_Characters[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ ";
	int i;
	for (i = 0; i < string_Lenght; i++)	{
		// If there is an invalid character then exit the program
		if (strchr(possible_Characters, string_tobe_Modified[i]) == 0)	{
			char errorMsg[] = "otp_enc error: input contains bad characters";
			fprintf(stderr, "%s\n", errorMsg);
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
    function to remove new line in the buffer and add semicolon
 ****************************************************************/
void remove_New_Line_from_Buffer(char *buffer, int buffer_Size){
	int i;
	for (i = 0; i < buffer_Size; i++){
		// Exit if we reached a null term
		if (buffer[i] == '\0')	{
			return;
		}
		// Replace new line with semicolon
		if (buffer[i] == '\n')	{
			buffer[i] = ';';
		}
	}
}
