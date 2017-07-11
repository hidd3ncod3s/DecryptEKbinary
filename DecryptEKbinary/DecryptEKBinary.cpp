#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>
#include <ctime>
#include "Utils.h"
#include "NuclearEK.h"
#include "AnglerEK.h"
#include "FiestaEK.h"
#include "GoonEK.h"
#include "SweetOrange.h"
#include "NeutrinoEK.h"
#include "UnknownEK1.h"
#include "Niteris_CottonCastle.h"

int main(int argc, char* argv[])
{
	FILE *fpdec=NULL;
	unsigned long encBufferSize= 0, writenCount= 0;
	unsigned char *encbuffer= NULL;

	if (argc < 2){
		printf("%s <inputfilename>", argv[0]);
		exit(-1);
	}

	srand(time(NULL));
	
	encbuffer= readBinaryFile(argv[1], &encBufferSize);
	if(!encbuffer){
		exit(-1);
	}

	if(isitaPEbinary(encbuffer, encBufferSize)){
		printf("No need to do anything.\n");
		goto finished;
	}

	if(DecryptNuclearBinary(encbuffer, encBufferSize))
		goto finished;

	if(DecryptAnglerBinary(encbuffer, encBufferSize))
		goto finished;

	if(DecryptFiestaBinary(encbuffer,encBufferSize))
		goto finished;

	if(DecryptGoonBinary(encbuffer,encBufferSize))
		goto finished;

	if(DecryptSweetOrangeBinary(encbuffer,encBufferSize))
		goto finished;

	if(DecryptNeutrinoBinary(encbuffer,encBufferSize))
		goto finished;

	if(DecryptUnknownEK_1_Binary(encbuffer,encBufferSize))
		goto finished;

	if(DecryptNiteris_CottonCastle_EK_HBinary(encbuffer,encBufferSize))
		goto finished;

	printf("Looks like a new encryption method.\n");

finished:
	free(encbuffer);
}