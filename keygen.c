/*******************************************************************************************************************
Tatyana Vlaskin (vlaskint@onid.oregonstate.edu)
CS344 Spring 2015
Program 4
Filename: keygen.c

Description:
Program creates a key file of specified length
Create a file of characters keyLength long with standard Unix randomization methods
Allowed characters are 26 characters of the alphabet and the space character
Do not add spaces between characters yourself

Adopted from:ask for refference

**********************************************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>

int main(int argc, char *argv[]){
	// Seed the random number generator
	srandom(time(NULL));
	char *randomized_String;
	//we need to make sure that there are qt least 2 arguments
	if (argc != 2)	{
		printf("not enough arguments were specified\n");
		exit(1);
	}
	// if there are 3 arguments, we do the following things:
	///Program creates a key file of specified length
    /// Create a file of characters keyLength long with standard Unix randomization methods
    ///Allowed characters are 26 characters of the alphabet and the space character
    ///Do not add spaces between characters yourself
	if (argc == 2){
		int string_Length;
		//convert string to numbers
		string_Length = atoi(argv[1]);
		randomized_String = (char*)malloc(sizeof(char)*(string_Length+1));
        static const char available_Characters[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ ";
        int i;
        for (i = 0; i < string_Length; i++) {
		// For each element in the string array put a random character using one of the available characters
	    randomized_String[i] = available_Characters[rand() % (sizeof(available_Characters) - 1)];
	}
	// Make the last element null terminated
	randomized_String[string_Length] = 0;
		printf("%s\n", randomized_String);
	}
	// Free the allocated string memory
	free(randomized_String);
	return 0;
}
