#ifndef EK_UTILS_H
#define EK_UTILS_H

#include "Includes.h"

void printhex(unsigned char *buffer, int keylength);
unsigned int isitaPEbinary(const unsigned char *binarybuffer, unsigned int binarylength);
unsigned char* readBinaryFile(char *filename, unsigned long *bufferlength);
bool isitaASCIIfile(const unsigned char *binary, unsigned int binarylength);

void rc4_init (unsigned char *key, unsigned int key_length);
unsigned char rc4_output();

#endif