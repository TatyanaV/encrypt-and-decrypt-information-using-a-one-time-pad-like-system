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
