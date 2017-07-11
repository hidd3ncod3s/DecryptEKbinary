#include "Includes.h"
#include "Utils.h"
#include <string>
#include <ctime>
#include "NeutrinoEK.h"

//Challenging one.
unsigned char knownRC4keys[][20]=	{ "wcgnpgtciq",     // Neutrino
	                                  "fxfdaxrrax",     // Neutrino
									  "fqryuznioo",     // Neutrino
									  "yadajzohqu",     // Neutrino
									  "jrwrssnzqn",     // Neutrino
									  "jryxkntmng",     // Neutrino
									  "fyzfvboqzw",     // 1st June 2015
									  "hruushsmqh",
									  "y0fz0r5qF2MT",   // Neutrino-ish - conf file
									  "BtWDIIjmC7ja3vs", // Neutrino-ish - exe
									  "jjobetgviq"
                                    };

bool DecryptNeutrinoBinary(const unsigned char *buffer, unsigned int bSize)
{
	bool foundBinary= false;
	unsigned int keyindex= 0;
	unsigned char *buffernew= NULL;
	std::string filename;
	FILE *fout=NULL;
	unsigned long writenCount= 0;

	while (!foundBinary && keyindex < _countof(knownRC4keys))
	{
		buffernew= (unsigned char*)calloc(1,bSize);
		if (!buffernew){
			printf("[ERROR] Neutrino EK: Error in allocating memory\n");
			return false;
		}

		memcpy(buffernew, buffer, bSize);

		rc4_init((unsigned char*)knownRC4keys[keyindex], strlen((const char*)&knownRC4keys[keyindex][0]));
		for (int index = 0; index < bSize; index++){
			buffernew[index] = buffer[index] ^ rc4_output();
		}

		if(isitaPEbinary(buffernew, bSize) || isitaASCIIfile(buffernew, bSize)){
			std::string randstr= std::to_string((long long)rand() % 1000 + 1);
				
			filename= "Neutrino_" + randstr +".bin";
			
			fout = fopen ( filename.c_str() , "wb" );
			if( !fout ) {
				perror("[ERROR]: Neutrino EK Error Opening file for writting\n");
				free(buffernew);
				return false;
			}

			writenCount= fwrite(buffernew, bSize, 1, fout);
			if( writenCount != 1){
				perror("[ERROR]: Neutrino EK Error in writting the full content\n");
				free(buffernew);
				return false;
			}

			fclose(fout);
			printf("[INFO] Found an Neutrino EK encrypted binary\n");
			free(buffernew);
			return true;
		}

		free(buffernew);
		buffernew= NULL;

		keyindex++;
	}
	return false;
}
