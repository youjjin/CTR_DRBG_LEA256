#include "CTR-DRBG_LEA-256.h"
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <assert.h>
#include <math.h>

#define len_seed 3

unsigned char CBC_Key_op[32] = {
	0x00, 0x01, 0x02, 0x03,
	0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B,
	0x0C, 0x0D, 0x0E, 0x0F,
	0x10, 0x11, 0x12, 0x13,
	0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1A, 0x1B,
	0x1C, 0x1D, 0x1E, 0x1F
};

void Instantiate_Function_op(STATE* state, unsigned char* entropy, unsigned int entropy_len, unsigned char* nonce, unsigned int nonce_len, unsigned char* personalization, unsigned int personalization_len)
{
	unsigned int seed_len = entropy_len + nonce_len + personalization_len;
	unsigned char seed_material[270] = { 0x00, };
	unsigned char seed[48] = { 0x00, }; //seed = key(32byte)||V(16byte)

	//유도함수를 사용하지 않는경우 개별화 문자열의 길이가 시드길이(48byte) 보다 짧으면 시드길이가 될때까지 0으로 패딩 시켜주려고 아래의 과정을 수행한다.
	unsigned char person[48] = { 0x00, };

	int i, j;

	/*유도함수를 사용하는 경우*/
	if (state->state_control.df_flag == 1)
	{
		//seed_material = entropy
		memcpy(seed_material, entropy, entropy_len);
		//seed_material = entropy||nonce
		memcpy(seed_material + entropy_len, nonce, nonce_len);
		//seed_material = entropy||nonce||personalization
		memcpy(seed_material + entropy_len + nonce_len, personalization, personalization_len);

		/*유도함수*/
		//seed_material을 넣고 seed 를 뽑아냄(48byte)
		DF_op(state, seed_material, entropy_len + nonce_len + personalization_len, seed, 48);

	}
	/*유도함수를 사용하지 않는 경우*/
	else
	{
		memcpy(person, personalization, personalization_len); //len_seed = 48이 될때까지 0으로 패딩
		unsigned char ent[48] = { 0x00, };//바이트를 같게하고 나머지를 0으로만들어서 xor해주려고..
		memcpy(ent, entropy, entropy_len);

		for (i = 0; i < 48; i++)
			seed[i] = ent[i] ^ person[i];
	}

	/*Key를 0으로 set*/
	memset(state->state_handle.Key, 0x00, 32);
	/*V를 0으로 set*/
	memset(state->state_handle.V, 0x00, 16);

	/*내부갱신함수*/
	//xor되어주는 값은 seed값!
	unsigned char key[32] = { 0x00, };
	memcpy(key, state->state_handle.Key, 32);

	unsigned char v[16] = { 0x00, };
	memcpy(v, state->state_handle.V, 16);

	unsigned char input_temp[48] = { 0x00, };
	memcpy(input_temp, seed, 48);

	unsigned char chaining_temp[48] = { 0x00, };
	unsigned char output_temp[48] = { 0x00, };
	unsigned char output_block[16] = { 0x00, };
	unsigned char one[1] = { 0x01 };


	/*1*/
	SUM_of_one(v, 16, one, 1, v);
	lea_encrypt(output_block, v, key);
	memcpy(chaining_temp, output_block, 16);
	/*2*/
	SUM_of_one(v, 16, one, 1, v);
	lea_encrypt(output_block, v, key);
	memcpy(chaining_temp + 16, output_block, 16);
	/*3*/
	SUM_of_one(v, 16, one, 1, v);
	lea_encrypt(output_block, v, key);
	memcpy(chaining_temp + 32, output_block, 16);

	for (i = 0; i < 48; i++)
	{
		output_temp[i] = chaining_temp[i] ^ input_temp[i];
	}

	memcpy(state->state_handle.Key, output_temp, 32);
	memcpy(state->state_handle.V, output_temp + 32, 16);

	state->state_handle.reseed_counter = 1;
}


void DF_op(STATE* state, unsigned char* input, unsigned int input_len, unsigned char* output, unsigned int output_len)
{
	int i, j, k;
	unsigned char L[4] = { input_len & 0xff000000, input_len & 0x00ff0000, input_len & 0x0000ff00, input_len & 0x000000ff };
	unsigned char N[4] = { output_len & 0xff000000, output_len & 0x00ff0000, output_len & 0x0000ff00, output_len & 0x000000ff };

	/* S = L(4-byte) || N(4-byte) || input(input_len-byte) || 0x80(1-byte) */
	int len = 8 + input_len + 1;
	int new_len = len;
	unsigned char S[1000] = { 0x00, };

	//S = L
	S[0] = L[0]; S[1] = L[1]; S[2] = L[2]; S[3] = L[3];
	//S = L || N
	S[4] = N[0]; S[5] = N[1]; S[6] = N[2]; S[7] = N[3];
	//S = L || N || input
	memcpy(S + 8, input, input_len);
	//S = L || N || input || 0x80
	S[8 + input_len] = 0x80;

	/*S의 길이가 블록길이의 배수가 되도록 0으로 오른쪽 패딩*/
	//일단 길이가 16(byte)의 배수가 되도록 맞춰줍니다..

	while ((new_len >> 4) != 0)
	{
		new_len++;
	}
	new_len = new_len + 16; //맨앞에 C를더해줄 아이

	//16의 배수가 된 len만큼의 배열을 0으로 초기화하여 생성
	unsigned char new_S[1000] = { 0x00, };
	unsigned char C_block[16] = { 0x00, };
	unsigned char C[4] = { 0x00, };
	unsigned char one[1] = { 0x01 };
	//new_S = C || 0(pad)
	memcpy(new_S, C_block, 16);
	//new_S = C || 0(pad) || S || 0(pad)
	memcpy(new_S + 16, S, len);

	unsigned char chaining_value[16] = { 0x00, };
	unsigned char input_block[16] = { 0x00, };
	unsigned char block[16] = { 0x00, };

	unsigned char temp[48] = { 0x00, };

	/*이제 시드길이 횟수만큼 반복할 것이다.*/
		/*1*/
	memset(chaining_value, 0x00, 16);
	for (j = 0; j < (new_len >> 4); j++)
	{
		memcpy(block, new_S + (j << 4), 16);
		/*0-16*/
		input_block[0] = chaining_value[0] ^ block[0]; input_block[1] = chaining_value[1] ^ block[1]; input_block[2] = chaining_value[2] ^ block[2]; input_block[3] = chaining_value[3] ^ block[3];
		input_block[4] = chaining_value[4] ^ block[4]; input_block[5] = chaining_value[5] ^ block[5]; input_block[6] = chaining_value[6] ^ block[6]; input_block[7] = chaining_value[7] ^ block[7];
		input_block[8] = chaining_value[8] ^ block[8]; input_block[9] = chaining_value[9] ^ block[9]; input_block[10] = chaining_value[10] ^ block[10]; input_block[11] = chaining_value[11] ^ block[11];
		input_block[12] = chaining_value[12] ^ block[12]; input_block[13] = chaining_value[13] ^ block[13]; input_block[14] = chaining_value[14] ^ block[14]; input_block[15] = chaining_value[15] ^ block[15];

		lea_encrypt(chaining_value, input_block, CBC_Key_op);
	}
	memcpy(temp, chaining_value, 16);
	SUM_of_one(C, 4, one, 1, C);
	memcpy(C_block, C, 4);
	//new_S = C || 0(pad)
	memcpy(new_S, C_block, 16);
	//new_S = C || 0(pad) || S || 0(pad)
	memcpy(new_S + 16, S, len);

	/*2*/
	memset(chaining_value, 0x00, 16);
	for (j = 0; j < (new_len >> 4); j++)
	{
		memcpy(block, new_S + (j << 4), 16);
		/*0-16*/
		input_block[0] = chaining_value[0] ^ block[0]; input_block[1] = chaining_value[1] ^ block[1]; input_block[2] = chaining_value[2] ^ block[2]; input_block[3] = chaining_value[3] ^ block[3];
		input_block[4] = chaining_value[4] ^ block[4]; input_block[5] = chaining_value[5] ^ block[5]; input_block[6] = chaining_value[6] ^ block[6]; input_block[7] = chaining_value[7] ^ block[7];
		input_block[8] = chaining_value[8] ^ block[8]; input_block[9] = chaining_value[9] ^ block[9]; input_block[10] = chaining_value[10] ^ block[10]; input_block[11] = chaining_value[11] ^ block[11];
		input_block[12] = chaining_value[12] ^ block[12]; input_block[13] = chaining_value[13] ^ block[13]; input_block[14] = chaining_value[14] ^ block[14]; input_block[15] = chaining_value[15] ^ block[15];

		lea_encrypt(chaining_value, input_block, CBC_Key_op);
	}
	memcpy(temp + 16, chaining_value, 16);
	SUM_of_one(C, 4, one, 1, C);
	memcpy(C_block, C, 4);
	//new_S = C || 0(pad)
	memcpy(new_S, C_block, 16);
	//new_S = C || 0(pad) || S || 0(pad)
	memcpy(new_S + 16, S, len);

	/*3*/
	memset(chaining_value, 0x00, 16);
	for (j = 0; j < (new_len >> 4); j++)
	{
		memcpy(block, new_S + (j << 4), 16);
		/*0-16*/
		input_block[0] = chaining_value[0] ^ block[0]; input_block[1] = chaining_value[1] ^ block[1]; input_block[2] = chaining_value[2] ^ block[2]; input_block[3] = chaining_value[3] ^ block[3];
		input_block[4] = chaining_value[4] ^ block[4]; input_block[5] = chaining_value[5] ^ block[5]; input_block[6] = chaining_value[6] ^ block[6]; input_block[7] = chaining_value[7] ^ block[7];
		input_block[8] = chaining_value[8] ^ block[8]; input_block[9] = chaining_value[9] ^ block[9]; input_block[10] = chaining_value[10] ^ block[10]; input_block[11] = chaining_value[11] ^ block[11];
		input_block[12] = chaining_value[12] ^ block[12]; input_block[13] = chaining_value[13] ^ block[13]; input_block[14] = chaining_value[14] ^ block[14]; input_block[15] = chaining_value[15] ^ block[15];

		lea_encrypt(chaining_value, input_block, CBC_Key_op);
	}
	memcpy(temp + 32, chaining_value, 16);
	SUM_of_one(C, 4, one, 1, C);
	memcpy(C_block, C, 4);
	//new_S = C || 0(pad)
	memcpy(new_S, C_block, 16);
	//new_S = C || 0(pad) || S || 0(pad)
	memcpy(new_S + 16, S, len);


	unsigned char key[32] = { 0x00, };
	unsigned char v[16] = { 0x00, };

	memcpy(key, temp, 32);
	memcpy(v, temp + 32, 16);
	memcpy(input_block, v, 16);

	unsigned char output_temp[48] = { 0x00, };

	/*1*/
	lea_encrypt(chaining_value, input_block, key);
	memcpy(output_temp, chaining_value, 16);
	memcpy(input_block, chaining_value, 16);
	memset(chaining_value, 0x00, 16);
	/*2*/
	lea_encrypt(chaining_value, input_block, key);
	memcpy(output_temp + 16, chaining_value, 16);
	memcpy(input_block, chaining_value, 16);
	memset(chaining_value, 0x00, 16);
	/*3*/
	lea_encrypt(chaining_value, input_block, key);
	memcpy(output_temp + 32, chaining_value, 16);
	memcpy(input_block, chaining_value, 16);
	memset(chaining_value, 0x00, 16);

	memcpy(output, output_temp, 48);
}

void Reseed_function_op(STATE* state, unsigned char* entropy, unsigned int entropy_len, unsigned char* additional, unsigned int additional_len)
{
	int i, j;
	unsigned char seed[48] = { 0x00, };
	unsigned char addition[48] = { 0x00, };
	unsigned char entro[48] = { 0x00, };

	if (state->state_control.df_flag == 1)
	{
		int len = entropy_len + additional_len;
		unsigned char seed_material[1000] = { 0x00, };

		//seed_material = entropy || additional
		memcpy(seed_material, entropy, entropy_len);
		memcpy(seed_material + entropy_len, additional, additional_len);
		DF_op(state, seed_material, len, seed, 48);
	}
	else
	{
		memcpy(entro, entropy, entropy_len);
		memcpy(addition, additional, additional_len);

		for (i = 0; i < 48; i++)
		{
			seed[i] = entro[i] ^ addition[i];
		}

	}

	/*내부갱신*/
	unsigned char key[32] = { 0x00, };
	memcpy(key, state->state_handle.Key, 32);
	unsigned char v[16] = { 0x00, };
	memcpy(v, state->state_handle.V, 16);
	unsigned char input_temp[48] = { 0x00, };
	memcpy(input_temp, seed, 48);

	unsigned char chaining_temp[48] = { 0x00, };
	unsigned char output_temp[48] = { 0x00, };
	unsigned char output_block[16] = { 0x00, };
	unsigned char one[1] = { 0x01 };

	/*1*/
	SUM_of_one(v, 16, one, 1, v);
	lea_encrypt(output_block, v, key);
	memcpy(chaining_temp, output_block, 16);
	/*2*/
	SUM_of_one(v, 16, one, 1, v);
	lea_encrypt(output_block, v, key);
	memcpy(chaining_temp + 16, output_block, 16);
	/*3*/
	SUM_of_one(v, 16, one, 1, v);
	lea_encrypt(output_block, v, key);
	memcpy(chaining_temp + 32, output_block, 16);

	for (i = 0; i < 48; i++)
	{
		output_temp[i] = chaining_temp[i] ^ input_temp[i];
	}

	memcpy(state->state_handle.Key, output_temp, 32);
	memcpy(state->state_handle.V, output_temp + 32, 16);

	state->state_handle.reseed_counter = 1;

}



void Generator_usePR_op(STATE* state, unsigned char* entropy, unsigned int entropy_len, unsigned char* additional, unsigned int additional_len, unsigned char* perseudorandom)
{
	int i, j;
	unsigned char key[32] = { 0x00, };
	unsigned char v[16] = { 0x00, };
	unsigned char addition[48] = { 0x00, };
	unsigned char one[1] = { 0x01 };
	unsigned int add_len = additional_len;

	unsigned char input_temp[48] = { 0x00, };
	unsigned char chaining_temp[48] = { 0x00, };
	unsigned char output_temp[48] = { 0x00, };
	unsigned char output_block[16] = { 0x00, };

	memcpy(key, state->state_handle.Key, 32);
	memcpy(v, state->state_handle.V, 16);

	/*외부갱신*/
	if (state->state_control.prediction_resisitance_flag == 1)
	{
		Reseed_function_op(state, entropy, entropy_len, additional, additional_len);

		additional_len = 0;
		additional = NULL;
	}

	if (additional != NULL)
	{
		if (state->state_control.df_flag == 1)
		{
			DF_op(state, additional, additional_len, addition, 48);
		}
		else if ((state->state_control.df_flag == 0) && (additional_len < 48))
		{
			memset(addition, 0x00, 48);
			memcpy(addition, additional, additional_len);
		}

		/*내부갱신*/
		memcpy(key, state->state_handle.Key, 32);
		memcpy(v, state->state_handle.V, 16);
		memcpy(input_temp, addition, 48);

		/*1*/
		SUM_of_one(v, 16, one, 1, v);
		lea_encrypt(output_block, v, key);
		memcpy(chaining_temp, output_block, 16);
		/*2*/
		SUM_of_one(v, 16, one, 1, v);
		lea_encrypt(output_block, v, key);
		memcpy(chaining_temp + 16, output_block, 16);
		/*3*/
		SUM_of_one(v, 16, one, 1, v);
		lea_encrypt(output_block, v, key);
		memcpy(chaining_temp + 32, output_block, 16);

		for (i = 0; i < 48; i++)
		{
			output_temp[i] = chaining_temp[i] ^ input_temp[i];
		}

		memcpy(state->state_handle.Key, output_temp, 32);
		memcpy(state->state_handle.V, output_temp + 32, 16);
	}


	unsigned char output[16] = { 0x00, };
	unsigned char randombits[128] = { 0x00, };
	unsigned char bf_V[16] = { 0x00, };

	memcpy(key, state->state_handle.Key, 32);
	memcpy(v, state->state_handle.V, 16);

	/*출력생성*/
	/*1*/
	SUM_of_one(v, 16, one, 1, v);
	lea_encrypt(output, v, key);
	memcpy(randombits, output, 16);
	/*2*/
	SUM_of_one(v, 16, one, 1, v);
	lea_encrypt(output, v, key);
	memcpy(randombits + 16, output, 16);
	/*3*/
	SUM_of_one(v, 16, one, 1, v);
	lea_encrypt(output, v, key);
	memcpy(randombits + 32, output, 16);
	/*4*/
	SUM_of_one(v, 16, one, 1, v);
	lea_encrypt(output, v, key);
	memcpy(randombits + 48, output, 16);
	/*5*/
	SUM_of_one(v, 16, one, 1, v);
	lea_encrypt(output, v, key);
	memcpy(randombits + 64, output, 16);
	/*6*/
	SUM_of_one(v, 16, one, 1, v);
	lea_encrypt(output, v, key);
	memcpy(randombits + 80, output, 16);
	/*7*/
	SUM_of_one(v, 16, one, 1, v);
	lea_encrypt(output, v, key);
	memcpy(randombits + 96, output, 16);
	/*8*/
	SUM_of_one(v, 16, one, 1, v);
	lea_encrypt(output, v, key);
	memcpy(randombits + 112, output, 16);

	memcpy(state->state_handle.V, v, 16);
	memcpy(state->state_handle.Key, key, 32);
	memcpy(perseudorandom, randombits, 128);

	/*내부갱신*/
	memcpy(key, state->state_handle.Key, 32);
	memcpy(v, state->state_handle.V, 16);
	memcpy(input_temp, addition, 48);

	/*1*/
	SUM_of_one(v, 16, one, 1, v);
	lea_encrypt(output_block, v, key);
	memcpy(chaining_temp, output_block, 16);
	/*2*/
	SUM_of_one(v, 16, one, 1, v);
	lea_encrypt(output_block, v, key);
	memcpy(chaining_temp + 16, output_block, 16);
	/*3*/
	SUM_of_one(v, 16, one, 1, v);
	lea_encrypt(output_block, v, key);
	memcpy(chaining_temp + 32, output_block, 16);

	for (i = 0; i < 48; i++)
	{
		output_temp[i] = chaining_temp[i] ^ input_temp[i];
	}

	memcpy(state->state_handle.Key, output_temp, 32);
	memcpy(state->state_handle.V, output_temp + 32, 16);
}


void Generator_noPR_op(STATE* state, unsigned char* additional, unsigned int additional_len, unsigned char* perseudorandom)
{
	int i, j;
	unsigned char key[32] = { 0x00, };
	unsigned char v[16] = { 0x00, };
	unsigned char addition[48] = { 0x00, };
	unsigned char one[1] = { 0x01 };
	unsigned int add_len = additional_len;

	unsigned char input_temp[48] = { 0x00, };
	unsigned char chaining_temp[48] = { 0x00, };
	unsigned char output_temp[48] = { 0x00, };
	unsigned char output_block[16] = { 0x00, };

	memcpy(key, state->state_handle.Key, 32);
	memcpy(v, state->state_handle.V, 16);

	/*외부갱신*/
	if (additional_len != 0)
	{
		if (state->state_control.df_flag == 1)
		{
			DF_op(state, additional, additional_len, addition, 48);
		}
		else if (state->state_control.df_flag == 0)
		{
			memcpy(addition, additional, additional_len);
		}

		/*내부갱신*/
		memcpy(key, state->state_handle.Key, 32);
		memcpy(v, state->state_handle.V, 16);
		memcpy(input_temp, addition, 48);

		/*1*/
		SUM_of_one(v, 16, one, 1, v);
		lea_encrypt(output_block, v, key);
		memcpy(chaining_temp, output_block, 16);
		/*2*/
		SUM_of_one(v, 16, one, 1, v);
		lea_encrypt(output_block, v, key);
		memcpy(chaining_temp + 16, output_block, 16);
		/*3*/
		SUM_of_one(v, 16, one, 1, v);
		lea_encrypt(output_block, v, key);
		memcpy(chaining_temp + 32, output_block, 16);

		for (i = 0; i < 48; i++)
		{
			output_temp[i] = chaining_temp[i] ^ input_temp[i];
		}

		memcpy(state->state_handle.Key, output_temp, 32);
		memcpy(state->state_handle.V, output_temp + 32, 16);
	}

	unsigned char bf_V[16] = { 0x00, };
	unsigned char output[16] = { 0x00, };
	unsigned char randombits[128] = { 0x00, };

	memcpy(key, state->state_handle.Key, 32);
	memcpy(v, state->state_handle.V, 16);

	/*출력생성*/
	/*1*/
	SUM_of_one(v, 16, one, 1, v);
	lea_encrypt(output, v, key);
	memcpy(randombits, output, 16);
	/*2*/
	SUM_of_one(v, 16, one, 1, v);
	lea_encrypt(output, v, key);
	memcpy(randombits + 16, output, 16);
	/*3*/
	SUM_of_one(v, 16, one, 1, v);
	lea_encrypt(output, v, key);
	memcpy(randombits + 32, output, 16);
	/*4*/
	SUM_of_one(v, 16, one, 1, v);
	lea_encrypt(output, v, key);
	memcpy(randombits + 48, output, 16);
	/*5*/
	SUM_of_one(v, 16, one, 1, v);
	lea_encrypt(output, v, key);
	memcpy(randombits + 64, output, 16);
	/*6*/
	SUM_of_one(v, 16, one, 1, v);
	lea_encrypt(output, v, key);
	memcpy(randombits + 80, output, 16);
	/*7*/
	SUM_of_one(v, 16, one, 1, v);
	lea_encrypt(output, v, key);
	memcpy(randombits + 96, output, 16);
	/*8*/
	SUM_of_one(v, 16, one, 1, v);
	lea_encrypt(output, v, key);
	memcpy(randombits + 112, output, 16);

	memcpy(state->state_handle.V, v, 16);
	memcpy(perseudorandom, randombits, 128);

	/*내부갱신*/
	memcpy(key, state->state_handle.Key, 32);
	memcpy(v, state->state_handle.V, 16);
	memcpy(input_temp, addition, 48);

	/*1*/
	SUM_of_one(v, 16, one, 1, v);
	lea_encrypt(output_block, v, key);
	memcpy(chaining_temp, output_block, 16);
	/*2*/
	SUM_of_one(v, 16, one, 1, v);
	lea_encrypt(output_block, v, key);
	memcpy(chaining_temp + 16, output_block, 16);
	/*3*/
	SUM_of_one(v, 16, one, 1, v);
	lea_encrypt(output_block, v, key);
	memcpy(chaining_temp + 32, output_block, 16);

	for (i = 0; i < 48; i++)
	{
		output_temp[i] = chaining_temp[i] ^ input_temp[i];
	}

	memcpy(state->state_handle.Key, output_temp, 32);
	memcpy(state->state_handle.V, output_temp + 32, 16);

}



void usePR_op(STATE* state, unsigned char* entropy, unsigned int entropy_len, unsigned char* entropy1, unsigned int entropy1_len, unsigned char* entropy2, unsigned int entropy2_len, unsigned char* nonce, unsigned int nonce_len, unsigned char*  personalization, unsigned int personalization_len, unsigned char* additional1, unsigned int additional1_len, unsigned char* additional2, unsigned int additional2_len, unsigned char* returned_bits)
{
	unsigned char random1[128] = { 0x00, };
	unsigned char random2[128] = { 0x00, };

	Instantiate_Function_op(state, entropy, entropy_len, nonce, nonce_len, personalization, personalization_len);
	Generator_usePR_op(state, entropy1, entropy1_len, additional1, additional1_len, random1);
	Generator_usePR_op(state, entropy2, entropy2_len, additional2, additional2_len, random2);
	memcpy(returned_bits, random2, 128);
}

void noPR_op(STATE* state, unsigned char* entropy, unsigned int entropy_len, unsigned char* nonce, unsigned int nonce_len, unsigned char* personalization, unsigned int personalization_len, unsigned char* entropyreseed, unsigned int entropyreseed_len, unsigned char* additionalreseed, unsigned int additionalreseed_len, unsigned char* additional1, unsigned int additional1_len, unsigned char* additional2, unsigned int additional2_len, unsigned char* returned_bits)
{
	unsigned char random1[128] = { 0x00, };
	unsigned char random2[128] = { 0x00, };

	Instantiate_Function_op(state, entropy, entropy_len, nonce, nonce_len, personalization, personalization_len);
	Reseed_function_op(state, entropyreseed, entropyreseed_len, additionalreseed, additionalreseed_len);
	Generator_noPR_op(state, additional1, additional1_len, random1);
	Generator_noPR_op(state, additional2, additional2_len, random2);
	memcpy(returned_bits, random2, 128);
}