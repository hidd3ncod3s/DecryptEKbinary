#include "Includes.h"
#include "Utils.h"
#include <string>
#include <ctime>
#include "FiestaEK.h"

#define KEY_LEN 256
//#define KEY_LEN 128

unsigned char * decryptmeMethod1(char *buffer, unsigned long bSize)
{
	unsigned char key[KEY_LEN]= {0x00};
	long index=0;
	int i=0;
	int gins=0;
	unsigned char *encrypted= NULL;

	printf("[INFO] Fiesta EK: Decrypting buffer of size: %d\n", bSize);

	if(bSize < KEY_LEN){
		return NULL;
	}

	printf("[INFO] Fiesta EK: Trying Key size: %d\n", KEY_LEN);
	memcpy(&key[0],(void*)&buffer[0], KEY_LEN);
	printhex(key, KEY_LEN);

	encrypted= (unsigned char*)&buffer[KEY_LEN];

	//printf("[INFO] Fiesta EK: Decrypting buffer of size: %d\n", bSize-KEY_LEN);

	for(; i < bSize-KEY_LEN; i++){
		index = index + 1 & 0xFF;
		gins = gins + key[index] & 0xFF;
		int j = key[index];
		key[index] = key[gins];
		key[gins] = (unsigned char)j;
		int k = key[index] + key[gins] & 0xFF;
		encrypted[i] = ((unsigned char)(encrypted[i] ^ key[k]));
	}
	printf("[INFO] Fiesta EK: Finished decrypting...\n");
	return encrypted;
}

unsigned char * decryptmeMethod2(char *buffer, unsigned long* bSize)
{
	//[first4 bytes is XOR key] [second fourbyte] [length (XOR with first four bytes)] [CRC]
	buffer+= 16;
	*bSize= *bSize - 16;
	buffer= (char*)decryptmeMethod1(buffer, *bSize);
	bool found= false;
	char *tmpbuffer= buffer;
	long tmpsize= *bSize;

	//return (unsigned char *)buffer;

	while(!found && tmpsize){
		while( *tmpbuffer != 0x4D){
			tmpbuffer += 1;
			tmpsize-= 1;
		}

		if( *(tmpbuffer + 1) == 0x5A){
			found= true;
			break;
		} else {
			tmpbuffer += 1;
			tmpsize-= 1;
		}
	}
	
	if(found){
		buffer= tmpbuffer;
		*bSize= tmpsize;
	}
	
	return (unsigned char *)buffer;
}

bool DecryptFiestaBinary(const unsigned char *buffer, unsigned int bSize)
{
	unsigned char *buffernew= NULL;
	unsigned char *decryptedbuffer=NULL;
	unsigned int first4= *(unsigned int*)buffer;
	unsigned int second4= *(unsigned int*)(buffer+4);
	unsigned long lSize= bSize;
	std::string filename;
	FILE *fout=NULL;
	unsigned long writenCount= 0;

	buffernew= (unsigned char*)calloc(1,lSize+1);
	if (!buffernew){
		printf("[ERROR] Fiesta EK: Error in allocating memory\n");
		return false;
	}

	memcpy(buffernew, buffer, lSize);

	if ((first4 ^ second4) == 0x50545346){
		printf("Using Method2\n");
		decryptedbuffer= decryptmeMethod2((char *)buffernew,&lSize);
	} else {
		printf("Using Method1\n");
		decryptedbuffer= decryptmeMethod1((char *)buffernew,lSize);
	}

	lSize-= KEY_LEN;


	if(isitaPEbinary(buffernew, bSize)){
		std::string randstr= std::to_string((long long)rand() % 1000 + 1);
				
		filename= "Fiesta_" + randstr +".bin";
			
		fout = fopen ( filename.c_str() , "wb" );
		if( !fout ) {
			perror("[ERROR]: Fiesta EK Error Opening file for writting\n");
			free(buffernew);
			return false;
		}

		writenCount= fwrite(decryptedbuffer, lSize, 1, fout);
		//writenCount= fwrite(buffernew, bSize, 1, fout);
		if( writenCount != 1){
			perror("[ERROR]: Fiesta EK Error in writting the full content\n");
			free(buffernew);
			return false;
		}

		fclose(fout);
		printf("[INFO] Found an Fiesta EK encrypted binary\n");
		free(buffernew);
		return true;
	}

	free(buffernew);
	return false;
}
