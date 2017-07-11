#include "Includes.h"
#include "Utils.h"
#include <string>
#include <ctime>
#include "AnglerEK.h"

#define KEY_LEN 8
static bool decryptme(char *buffer, long bSize)
{
	unsigned char key[KEY_LEN]= {0x00};
	long index=0;
	int i=0;
	long remainingCount= bSize%8;

	if(bSize < 48){
		return false;
	}

	memcpy(&key[0],(void*)&buffer[0x20], KEY_LEN);

	printhex(key, KEY_LEN);

	for(; index < bSize-remainingCount;){
		for(i=0; i < KEY_LEN;i++) 
			buffer[index+i] ^= key[i];

		index = index + KEY_LEN;
		
	}

	for(i=0; i < remainingCount;i++) 
		buffer[index+i] ^= key[i];
	
	return true;
}

//unsigned int keys[4]= {0x47763879, 0x33767545, 0x66706F58, 0x65443372}; // flash exploit CVE_2015_0313 or CVE_2015_0310
//unsigned int keys[4]= {0x73556246, 0x344D4A63, 0x4147736E, 0x59664365}; // silverlight vuln 
//unsigned int keys[4]= {0x64306C7A, 0x306D4761, 0x736B5443, 0x696F5345}; // flash exploit CVE_2015_0313 or CVE_2015_0310
//unsigned int keys[4]= {0x39525143, 0x75487832, 0x57645730, 0x79356332}; // IE vuln uses urlmon.dll functions. (CVE-2013-2551)
//unsigned int keys[4]= {0x4A397544, 0x6B67424F, 0x477A6662, 0x46466D76};   // IE vuln (CVE-2014-6332) Uses winhttp.dll function

unsigned int anglerkeys[][4]=	{
									{0x47763879, 0x33767545, 0x66706F58, 0x65443372},
									{0x73556246, 0x344D4A63, 0x4147736E, 0x59664365},
									{0x64306C7A, 0x306D4761, 0x736B5443, 0x696F5345},
									{0x39525143, 0x75487832, 0x57645730, 0x79356332},
									{0x4A397544, 0x6B67424F, 0x477A6662, 0x46466D76},
									{0x7461736F, 0x7048666A, 0x43656679, 0x6F764131}
								};

unsigned int __stdcall decryptthis(unsigned char* buffer, int index)
{
  unsigned char * originalbufferpointer; 
  unsigned int firstdword;
  unsigned int seconddword_and_result;
  signed int count; 
  unsigned int curvalue; 

  originalbufferpointer = buffer;
  firstdword = *(unsigned int *)buffer;
  seconddword_and_result = *(unsigned int *)(buffer + 4);
  curvalue = 0xC6EF3720;
  count = 32;
  do
  {
    seconddword_and_result -= curvalue + anglerkeys[index][((curvalue >> 11) & 3)] ^ (firstdword + (16 * firstdword ^ (firstdword >> 5)));
	curvalue += 0x61C88647;
    firstdword -= (curvalue + anglerkeys[index][curvalue & 3]) ^ (seconddword_and_result + (16 * seconddword_and_result ^ (seconddword_and_result >> 5)));
    --count;
  } while ( count );

  *(unsigned int *)originalbufferpointer = firstdword;
  *(unsigned int *)(originalbufferpointer + 4) = seconddword_and_result;
  return seconddword_and_result;
}

bool DecryptAnglerBinary(const unsigned char *buffer, unsigned int bSize)
{
	unsigned int keyindex= 0;
	unsigned long count = 0;
	FILE *fout=NULL;
	unsigned long writenCount= 0;
	std::string filename;
	unsigned char *buffernew= NULL;
	bool foundBinary= false;

	while (!foundBinary && keyindex < _countof(anglerkeys))
	{
		printf("[INFO] Angler EK: Key index= %d\n", keyindex);
		buffernew= NULL;

		buffernew= (unsigned char*)calloc(1,bSize+16);
		if (!buffernew){
			printf("[ERROR] Angler EK: Error in allocating memory\n");
			return false;
		}

		memcpy(buffernew, buffer, bSize);

		count = 0;
		//printf("bSize= %d\n", bSize);
		while (count < bSize){
			decryptthis(buffernew+count, keyindex);
			//printf("count= %d\n", count);
			count += 8;
			//if( count+8 > bSize)
			//	break;
		}

		unsigned int MZindex= 0;
		MZindex= isitaPEbinary(buffernew, bSize);
		if(MZindex){
			filename= std::to_string((long long)keyindex);

			std::string randstr= std::to_string((long long)rand() % 1000 + 1);
				
			filename= "Angler_" + filename + "_" + randstr +".bin";
			
			fout = fopen ( filename.c_str() , "wb" );
			if( !fout ) {
				perror("[ERROR] Angler EK: Error Opening file for writting\n");
				free(buffernew);
				return false;
			}

			writenCount= fwrite(buffernew, bSize, 1, fout);
			if( writenCount != 1){
				perror("[ERROR] Angler EK: Error in writting the full content\n");
				free(buffernew);
				return false;
			}

			fclose(fout);
			//goto jmphere;
			foundBinary= true;
			printf("[INFO] Found an Angler EK encrypted binary\n");

			unsigned int *pestart= NULL;
			unsigned int peSize= 0;
			unsigned int peFilesCount= 0;

			if (buffernew[0] == 'M' && buffernew[1]== 'Z'){
				printf("[INFO] Angler EK: We have got a binary straight.\n");
			} else {
				printf("[INFO] Angler EK: MZindex= %d\n", MZindex);
				MZindex= MZindex - 78;
				while (buffernew[MZindex] == 'M' && buffernew[MZindex+1]== 'Z'){
					printf("[INFO] Angler EK: Found a start of binary.\n");
					peSize= *(unsigned int*)(&buffernew[MZindex-4]);
					printf("[INFO] Angler EK: PE file is of size: %x.\n", peSize);

					if(peSize == 0){
						printf("[INFO] Angler EK: End of file reached.\n");
						break;
					}

					if ( (MZindex + peSize) > bSize){
						printf("[ERROR] Angler EK: Looks like a corrupted file.\n");
						break;
					}

					filename= std::to_string((long long)keyindex);
					filename= "Angler_" + filename + "_" + randstr + "_" + std::to_string((long long)peFilesCount) + ".bin";
			
					fout = fopen ( filename.c_str() , "wb" );
					if( !fout ) {
						perror("[ERROR] Angler EK: Error Opening PE file for writting\n");
						free(buffernew);
						return false;
					}

					writenCount= fwrite(&buffernew[MZindex], peSize, 1, fout);
					if( writenCount != 1){
						perror("[ERROR] Angler EK: Error in writting the full PE content\n");
						free(buffernew);
						return false;
					}

					fclose(fout);

					MZindex= MZindex + peSize + 4 /* Size of next length.*/;
					peSize= *(unsigned int*)(&buffernew[MZindex-4]); // next peSize
					if(peSize == 0){
						printf("[INFO] Angler EK: End of file reached.\n");
						break;
					}

					peFilesCount++;
					//exit(-1);
				}
			}
		}
jmphere:
		free(buffernew);
		buffernew= NULL;
		writenCount= 0;

		keyindex++;
	}
	
	return foundBinary;
}