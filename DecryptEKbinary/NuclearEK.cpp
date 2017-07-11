#include "Includes.h"
#include "Utils.h"
#include <string>
#include <ctime>
#include "NuclearEK.h"

//inmemory decrypt.
static bool decryptNuclear(unsigned char *buffer, unsigned long bSize, unsigned int keylen)
{
	unsigned char *key= NULL;
	unsigned long index=0;
	unsigned int i=0;
	unsigned long remainingCount= bSize%keylen;

	key = (unsigned char*)calloc( 1, keylen );
	if( !key ){
		fputs("[ERROR] Nuclear EK: Memory alloc fails",stderr);
		return false;
	}

	// use 0x20 to 0x3B
	memcpy(&key[0],(void*)&buffer[(0x20+keylen-1) - ((0x20+keylen-1)%keylen)], keylen);

	printf("[INFO] Nuclear EK: Trying with keylen= %d\n\t", keylen);
	printhex(key, keylen);

	for(index=0; index < bSize-remainingCount;){
		for(i=0; i < keylen;i++) 
			buffer[index+i] ^= key[i];

		index = index + keylen;
	}

	for(i=0; i < remainingCount;i++) 
		buffer[index+i] ^= key[i];
	
	return true;
}

#define MAX_KEY_LEN 16

bool DecryptNuclearBinary(const unsigned char *buffer, unsigned int bSize)
{
	int keylen= 1;
	std::string filename;
	unsigned char *buffernew= NULL;
	FILE *fout=NULL;
	bool foundBinary= false;

	while (!foundBinary && keylen < MAX_KEY_LEN)
	{
		//printf("Trying = %d\n", index);
		buffernew= NULL;

		buffernew= (unsigned char*)calloc(1,bSize+16);
		if (!buffernew){
			printf("[ERROR] Nuclear EK: Error in allocating memory\n");
			return false;
		}

		memcpy(buffernew, buffer, bSize);

		if (decryptNuclear(buffernew, bSize, keylen)){

			if(isitaPEbinary(buffernew, bSize)){

				filename= std::to_string((long long)keylen);
				std::string randstr= std::to_string((long long)rand() % 1000 + 1);
				
				filename= "Nuclear_" + filename + "_" + randstr +".bin";

				fout = fopen ( filename.c_str() , "wb" );
				if( !fout ) {
					perror("[ERROR] Nuclear EK: Error Opening file for writting\n");
					free(buffernew);
					return false;
				}

				int writenCount= fwrite(buffernew, bSize, 1, fout);
				if( writenCount != 1){
					perror("[ERROR] Nuclear EK: Error in writting the full content\n");
					free(buffernew);
					return false;
				}

				fclose(fout);
				foundBinary= true;
				printf("[INFO] Found an Nuclear EK encrypted binary\n");
			}
		}

		free(buffernew);
		buffernew= NULL;
		fout=NULL;

		keylen++;
	}

	return foundBinary;
}