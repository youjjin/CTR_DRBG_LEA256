#include "CTR-DRBG_LEA-256.h"
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <assert.h>
#include <math.h>

unsigned int cpucycles(void) { return __rdtsc(); }


void main()
{
	STATE state;
	state.state_control.df_flag = 0;
	state.state_control.prediction_resisitance_flag = 0;
	unsigned char Entropy[48] = { 0x05, 0x45, 0x80, 0x08, 0x31, 0x24, 0xF4, 0xBA, 0x34, 0x15, 0x72, 0x8D, 0x1B, 0x7E, 0x19, 0x2D, 0xB5, 0x86, 0xC7, 0x19, 0x52, 0xC9, 0xF2, 0xFB, 0xC9, 0x50, 0xD3, 0x35, 0xC0, 0xC0, 0xCA, 0xBC, 0x27, 0xD1, 0xFE, 0x29, 0x06, 0x02, 0x44, 0x0D, 0x79, 0x8C, 0x42, 0x85, 0xF8, 0x94, 0xD4, 0x0F };
	unsigned char* Nonce = NULL;
	unsigned char* PersonalizationString = NULL;
	unsigned char EntropyReseed[48] = { 0xDC, 0xA4, 0xAE, 0x9C, 0x1F, 0x5C, 0x43, 0xE7, 0x64, 0x65, 0xE6, 0x04, 0x37, 0xA7, 0x2F, 0x3C, 0x95, 0xBC, 0xA1, 0x18, 0xAF, 0xA4, 0x89, 0xBC, 0xEB, 0xBA, 0x29, 0x76, 0x2C, 0xE6, 0x16, 0x97, 0x53, 0x15, 0xDF, 0x82, 0x06, 0xE6, 0xEF, 0x02, 0xB0, 0xA6, 0xB5, 0xE1, 0xC8, 0x7F, 0x02, 0xB6 };
	unsigned char* AdditionalReseed = NULL;
	unsigned char* Additional1 = NULL;
	unsigned char* Additional2 = NULL;
	unsigned char randombits[128] = { 0x00, };
	//ReturnedBits = 4B3EA2BDE2589643997AEDFEAE7A09C26116FF5D6E07D41FB88E3415BCC0FA1A120CC24ECBA114A62E10F1960359C8C62DEDDAF3926E924F5326AB5A830C8B57DA08927CF32F28ADE0FB838817C64652FC4CD2BCB331DA78E9405B536A97F1786B8298594EC214BDCA978FD519189AE8A545AE85B1AA2B1B234D95C6C188840C

	int i;
	unsigned long long cycles = 0;
	unsigned long long cycles1 = 0;
	unsigned long long cycles2 = 0;
	unsigned int loop = 10000;

	//for loop에 들어가는 것까지 안새주려고 시간을 포루프 안에서 돌려줄것이다.
	for (i = 0; i < loop; i++)
	{
		cycles1 = cpucycles();
		noPR_op(&state, Entropy, 48, Nonce, 0, PersonalizationString, 0, EntropyReseed, 48, AdditionalReseed, 0, Additional1, 0, Additional2, 0, randombits);

		cycles2 = cpucycles();
		cycles += (cycles2 - cycles1);
	}

	printf("\n[loop = %d]cycles : %10lld\n", loop, cycles / loop);
	cycles = 0;


	printf("난수\n");
	for (int A = 0; A < 128; A++)
		printf("%02X ", randombits[A]);
	printf("\n");

	//LEA_DRBG_LEA256_usePR_useDF_Test(); //정답
	//LEA_DRBG_LEA256_noPR_useDF_Test();//98DDCC => 정답
	//LEA_DRBG_LEA256_usePR_noDF_Test(); // => 76EEB2땡 // 6F2108D //52D3CF
	//LEA_DRBG_LEA256_noPR_noDF_Test(); // 4B3EA 정답이 아님

}