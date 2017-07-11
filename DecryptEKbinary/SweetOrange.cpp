#include "Includes.h"
#include "Utils.h"
#include <string>
#include <ctime>
#include "SweetOrange.h"

#define KEY_LEN 8
#define KEY "investor"
//#define KEY {0xB9, 0x32, 0xAA, 0x6f, 0xc8, 0x45, 0x4c, 0x0B}

static bool decryptme(char *buffer, long bSize)
{
	int i = 0;
    int curkeyindex = 0;
    int keylength = 0;
    int m = 0;
    int doDecrypt = 0;
    int i1 = 0;
    char keyBytes[] = KEY;
    keylength = KEY_LEN;
    i = 0;
    curkeyindex = 0;
    while (i < bSize)
    {
      i = 0;
      curkeyindex = 0;
      while (i < bSize)
      {
        doDecrypt = 1;
        if (i % 2 == 0)
        {
          i1++;
          if (i1 == keylength)
          {
            i1 = 0;
            doDecrypt = 0;
          }
        }
        if (buffer[i] == 0) {
          doDecrypt = 0;
        }
        if (buffer[i] == keyBytes[curkeyindex]) {
          doDecrypt = 0;
        }
        if (doDecrypt == 1)
        {
          int i2 = buffer[i];
          int i3 = keyBytes[curkeyindex];
          m = (char)(i2 ^ i3);
          buffer[i] = m;
        }
        if (curkeyindex < keylength - 1) {
          curkeyindex++;
        } else {
          curkeyindex = 0;
        }
        i++;
      }
      i++;
    }

	return true;
}

bool DecryptSweetOrangeBinary(const unsigned char *buffer, unsigned int bSize)
{
	unsigned char *buffernew= NULL;
	std::string filename;
	FILE *fout=NULL;
	unsigned long writenCount= 0;

	buffernew= (unsigned char*)calloc(1,bSize+1);
	if (!buffernew){
		printf("[ERROR] SweetOrange EK: Error in allocating memory\n");
		return false;
	}

	memcpy(buffernew, buffer, bSize);
	decryptme((char *)buffernew,bSize);

	if(isitaPEbinary(buffernew, bSize)){
		std::string randstr= std::to_string((long long)rand() % 1000 + 1);
				
		filename= "SweetOrange_" + randstr +".bin";
			
		fout = fopen ( filename.c_str() , "wb" );
		if( !fout ) {
			perror("[ERROR]: SweetOrange EK Error Opening file for writting\n");
			free(buffernew);
			return false;
		}

		writenCount= fwrite(buffernew, bSize, 1, fout);
		if( writenCount != 1){
			perror("[ERROR]: SweetOrange EK Error in writting the full content\n");
			free(buffernew);
			return false;
		}

		fclose(fout);
		printf("[INFO] Found an SweetOrange EK encrypted binary\n");
		free(buffernew);
		return true;
	}

	free(buffernew);
	return false;
}