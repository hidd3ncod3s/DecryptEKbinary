#include "Includes.h"

void printhex(unsigned char *buffer, int keylength)
{
	int i=0;
	
	for(; i < keylength; i++)
		printf("0x%02x ", buffer[i]);
	printf("\n");
}

bool isitaASCIIfile(const unsigned char *binary, unsigned int binarylength)
{
	unsigned int index=0;

	if (binarylength == 0)
		return false;

	while(index < binarylength){
		if (binary[index] & 0x80)
			return false;
		index++;
	}

	return true;
}

// Only Angler and Unknown EK 1 uses the Index returned by this function.
// TODO: Improve this function.
unsigned int isitaPEbinary(const unsigned char *binary, unsigned int binarylength)
{
	unsigned int index=0;

	if (binarylength == 0)
		return 0;

	if (binarylength > 2 && binary[0] == 'M' && binary[1] == 'Z')
		printf("[INFO] First two bytes are MZ.\n");

	//This program cannot
	while(index < binarylength){
		if( (index+19) >= binarylength)
			break;

		if ((binary[index] == 'T' || binary[index] == 't') &&
			(binary[index+1] == 'h' || binary[index+1] == 'H') &&
			((binary[index+2] == 'i' || binary[index+2] == 'I') ||
			(binary[index+2] == 'a' || binary[index+2] == 'A')) &&
			((binary[index+3] == 's' || binary[index+3] == 'S') ||
			(binary[index+3] == 't' || binary[index+3] == 'T')) && // RIG/Goon
			(binary[index+4] == ' ' || binary[index+4] == ' ') &&
			(binary[index+5] == 'p' || binary[index+5] == 'P') &&
			(binary[index+6] == 'r' || binary[index+6] == 'R') &&
			(binary[index+7] == 'o' || binary[index+7] == 'O') &&
			(binary[index+8] == 'g' || binary[index+8] == 'G') &&
			(binary[index+9] == 'r' || binary[index+9] == 'R') &&
			(binary[index+10] == 'a' || binary[index+10] == 'A') &&
			(binary[index+11] == 'm' || binary[index+11] == 'M') &&
			(binary[index+12] == ' ')                            &&
			(binary[index+13] == 'c' || binary[index+13] == 'C') &&
			(binary[index+14] == 'a' || binary[index+14] == 'A') &&
			(binary[index+15] == 'n' || binary[index+15] == 'N') &&
			(binary[index+16] == 'n' || binary[index+16] == 'N') &&
			(binary[index+17] == 'o' || binary[index+17] == 'O') &&
			(binary[index+18] == 't' || binary[index+18] == 'T') &&
			(binary[index+19] == ' ' || binary[index+19] == ' ') &&
			(binary[index+20] == 'b' || binary[index+20] == 'B') &&
			(binary[index+21] == 'e' || binary[index+21] == 'E') &&
			(binary[index+22] == ' ')                            &&
			(binary[index+23] == 'r' || binary[index+23] == 'R') &&
			(binary[index+24] == 'u' || binary[index+24] == 'U') &&
			(binary[index+25] == 'n' || binary[index+25] == 'N')
		   )
		   return index;
		index++;
	}

	index= 0;
	while(index+1 < binarylength){
		if (binary[index] == 'M' && binary[index+1] == 'Z'){
			if ((binarylength-index) > 0xEF){
				unsigned int peoffset= *(unsigned int*)(&binary[index+0x3C]);
				if (index+peoffset+1 > binarylength){
					printf("[INFO] Probably corrupted.\n");
					index++;
					continue;
				}

				if (binary[index+peoffset] == 'P' && binary[index+peoffset+1] == 'E'){
					printf("[INFO] Found MZ and PE bytes.\n");
					return index + 0x4E; // 0x4e == 78
				}
			}
			printf("[INFO] Found MZ bytes but didn't find the PE bytes.\n");
		}
		index++;
	}

	return 0;
}

unsigned char* readBinaryFile(char *filename, unsigned long *bufferlength)
{
	FILE *fpenc= NULL;
	unsigned long lSize= 0;
	unsigned char *encbuffer= NULL;

	if (!filename || !bufferlength)
		return NULL;

	fpenc = fopen ( filename , "rb" );
	if( !fpenc ) {
		perror("Eror opening the file for reading.\n");
		return NULL;
	}

	fseek( fpenc , 0L , SEEK_END);
	lSize = ftell( fpenc );
	rewind( fpenc );

	/* allocate memory for entire content */
	encbuffer = (unsigned char*)calloc( 1, lSize );
	if( !encbuffer ){
		fclose(fpenc);
		fputs("memory alloc fails",stderr);
		return NULL;
	}

	/* copy the file into the buffer */
	if( 1!=fread( encbuffer , lSize, 1 , fpenc) ){
	  fclose(fpenc);
	  free(encbuffer);
	  fputs("entire read fails",stderr);
	  return NULL;
	}

	fclose(fpenc);

	*bufferlength= lSize;
	return encbuffer;
}

unsigned char S [0x100]; // dec 256
unsigned int i, j;
void rc4_init (unsigned char *key, unsigned int key_length) 
{
     for (i = 0; i < 0x100; i++)
          S[i] = i;
          for (i = j = 0; i < 0x100; i++) {
               unsigned char temp;
               j = (j + key[i % key_length] + S[i]) & 0xFF;
               temp = S[i];
               S[i] = S[j];
               S[j] = temp;
          }
          i = j = 0;
}

unsigned char rc4_output() 
{
     unsigned char temp;
     i = (i + 1) & 0xFF;
     j = (j + S[i]) & 0xFF;
     temp = S[i];
     S[i] = S[j];
     S[j] = temp;
     return S[(S[i] + S[j]) & 0xFF];
}