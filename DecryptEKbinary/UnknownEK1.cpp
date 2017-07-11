#include "Includes.h"
#include "Utils.h"
#include <string>
#include <ctime>
#include "UnknownEK1.h"

/*
The way it works is, it directly jumps to 0x2000 and checks whether the first two bytes equal to 0x7777.
If so, the next byte is the xor key and and skipping one byte , the next four bytes is the total length of the 
executable code/file. Once you are done with the xor, it runs the shellcode from the start of the buffer and loads the embedded DLL.
*/
bool DecryptUnknownEK_1_Binary(const unsigned char *buffer, unsigned int bSize)
{
	unsigned int remainingByteCount= bSize;

	if (bSize < 0x2000){
		return false;
	}

	remainingByteCount -= 0x2000;

	if (*((unsigned short*)&buffer[0x2000]) == 0x7777){

		if (remainingByteCount < 2)
			return false;

		unsigned char xorkey= *((unsigned char*)&buffer[0x2002]);
		remainingByteCount -= 0x2;

		unsigned int binarylength= *((unsigned int*)&buffer[0x2004]);
		remainingByteCount -= 0x4;

		if (binarylength > remainingByteCount)
			return false;

		printf("UnknownEK 1 binary XOR key= 0x%x\n", xorkey);
		printf("UnknownEK 1 binary length= %d\n", binarylength);

		unsigned char*buffernew= (unsigned char*)calloc(1,binarylength);
		if (!buffernew){
			printf("[ERROR] Unknown EK 1: Error in allocating memory\n");
			return false;
		}

		memcpy(buffernew, &buffer[0x2008], binarylength);

		for(int index= 0; index < binarylength; index++) buffernew[index]= buffernew[index] ^ xorkey;

		unsigned int foundIndex= isitaPEbinary(buffernew, bSize);
		if(foundIndex > 0){
			FILE *fout=NULL;
			std::string filename;
			unsigned long writenCount= 0;

			//binarylength= remainingByteCount - (foundIndex - 78); // adjust the binary length
			binarylength= *((unsigned int*)&buffernew[foundIndex - 82]);

			std::string randstr= std::to_string((long long)rand() % 1000 + 1);
				
			filename= "UnknownEK_1_" + randstr +".bin";
			
			fout = fopen ( filename.c_str() , "wb" );
			if( !fout ) {
				perror("[ERROR]: UnknownEK_1 EK Error Opening file for writting\n");
				free(buffernew);
				return false;
			}

			writenCount= fwrite(&buffernew[foundIndex - 78], binarylength, 1, fout);
			//writenCount= fwrite(buffernew, bSize, 1, fout);
			if( writenCount != 1){
				perror("[ERROR]: UnknownEK_1 EK Error in writting the full content\n");
				free(buffernew);
				return false;
			}

			fclose(fout);
			printf("[INFO] Found an UnknownEK_1 encrypted binary\n");
			free(buffernew);
			return true;
		}

		free(buffernew);
		return true;
	}

	return false;
}