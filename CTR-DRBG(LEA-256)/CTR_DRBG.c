#include "CTR-DRBG_LEA-256.h"
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <assert.h>
#include <math.h>

#define len_seed 3

unsigned char CBC_Key[32] = {
	0x00, 0x01, 0x02, 0x03,
	0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B,
	0x0C, 0x0D, 0x0E, 0x0F,
	0x10, 0x11, 0x12, 0x13,
	0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1A, 0x1B,
	0x1C, 0x1D, 0x1E, 0x1F
};

void SUM_of_one(unsigned char* input1, unsigned int len1, unsigned char* input2, unsigned int len2, unsigned char* output)
{
	unsigned int len;
	unsigned int sum = 0;
	unsigned char carry = 0x00;
	int j = 0;

	if (len1 >= len2)
		len = len1;
	else
		len = len2;

	unsigned char* string1 = (unsigned char*)calloc(len, sizeof(unsigned char));
	unsigned char* string2 = (unsigned char*)calloc(len, sizeof(unsigned char));

	memcpy(string1 + (len - len1), input1, len1);
	memcpy(string2 + (len - len2), input2, len2);

	int i;
	for (i = len - 1; i >= 0; i--)
	{
		sum = string1[i] + string2[i] + carry;

		if (sum > 0xff)
			carry = 0x01;
		else
			carry = 0x00;

		output[i] = sum & 0xff;
	}
}

void Instantiate_Function(STATE* state, unsigned char* entropy, unsigned int entropy_len, unsigned char* nonce, unsigned int nonce_len, unsigned char* personalization, unsigned int personalization_len)
{
	unsigned int seed_len = entropy_len + nonce_len + personalization_len;
	unsigned char* seed_material = (unsigned char*)calloc(seed_len, sizeof(unsigned char));
	unsigned char seed[48] = { 0x00, }; //seed = key(32byte)||V(16byte)
	//유도함수를 사용하지 않는경우 개별화 문자열의 길이가 시드길이(48byte) 보다 짧으면 시드길이가 될때까지 0으로 패딩 시켜주려고 아래의 과정을 수행한다.
	unsigned char person[48] = { 0x00, };
	int i;
	/*유도함수를 사용하는 경우*/
	if (state->state_control.df_flag == 1)
	{
		//seed_material = entropy
		for (i = 0; i < entropy_len; i++)
			seed_material[i] = entropy[i];
		//seed_material = entropy||nonce
		for (i = entropy_len; i < (entropy_len + nonce_len); i++)
			seed_material[i] = nonce[i - entropy_len];
		//seed_material = entropy||nonce||personalization
		for (i = (entropy_len + nonce_len); i < (entropy_len + nonce_len + personalization_len); i++)
			seed_material[i] = personalization[i - (entropy_len + nonce_len)];
		/*유도함수*/
		//seed_material을 넣고 seed 를 뽑아냄(48byte)
		DF(state, seed_material, entropy_len + nonce_len + personalization_len, seed, 48);
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
	for (i = 0; i < 32; i++)
		state->state_handle.Key[i] = 0x00;
	/*V를 0으로 set*/
	for (i = 0; i < 16; i++)
		state->state_handle.V[i] = 0x00;
	/*내부갱신함수*/
	//xor되어주는 값은 seed값!
	Update(state, seed, 48);
	state->state_handle.reseed_counter = 1;
	free(seed_material);
}


/*유도함수*/ //임의의 길이를 입력받아서 씨드 길이(48byte)의 출력을 생성하는 일종의 해시함수
void DF(STATE* state, unsigned char* input, unsigned int input_len, unsigned char* output, unsigned int output_len)
{
	int i, j, k;
	unsigned char L[4] = { input_len & 0xff000000, input_len & 0x00ff0000, input_len & 0x0000ff00, input_len & 0x000000ff };
	unsigned char N[4] = { output_len & 0xff000000, output_len & 0x00ff0000, output_len & 0x0000ff00, output_len & 0x000000ff };
	/* S = L(4-byte) || N(4-byte) || input(input_len-byte) || 0x80(1-byte) */
	int len = 4 + 4 + input_len + 1;
	int new_len = len;
	unsigned char* S = (unsigned char*)calloc(len, sizeof(unsigned char));
	//S = L
	for (i = 0; i < 4; i++)
		S[i] = L[i];
	//S = L || N
	for (i = 4; i < 8; i++)
		S[i] = N[i - 4];
	//S = L || N || input
	for (i = 8; i < 8 + input_len; i++)
		S[i] = input[i - 8];
	//S = L || N || input || 0x80
	S[8 + input_len] = 0x80;

	/*S의 길이가 블록길이의 배수가 되도록 0으로 오른쪽 패딩*/
	//일단 길이가 16(byte)의 배수가 되도록 맞춰줍니다..
	while (new_len % 16 != 0)
	{
		new_len++;
	}
	new_len = new_len + 16; //맨앞에 C를더해줄 아이
	//16의 배수가 된 len만큼의 배열을 0으로 초기화하여 생성
	unsigned char* new_S = (unsigned char*)calloc(new_len, sizeof(unsigned char));
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
	for (i = 0; i < 3; i++)
	{
		for(int A = 0; A < 16; A++)
			chaining_value[A] = 0x00;

		for (j = 0; j < (new_len / 16); j++)
		{
			memcpy(block, new_S + (j * 16), 16);

			for (k = 0; k < 16; k++)
			{
				input_block[k] = chaining_value[k] ^ block[k];
			}

			lea_encrypt(chaining_value, input_block, CBC_Key);
		}
		memcpy(temp + (i * 16), chaining_value, 16);
		SUM_of_one(C, 4, one , 1, C);
		memcpy(C_block, C, 4);
		//new_S = C || 0(pad)
		memcpy(new_S, C_block, 16);
		//new_S = C || 0(pad) || S || 0(pad)
		memcpy(new_S + 16, S, len);
	}

	unsigned char key[32] = { 0x00, };
	unsigned char v[16] = { 0x00, };

	for (i = 0; i < 32; i++)
		key[i] = temp[i];

	for (i = 32; i < 48; i++)
		v[i-32] = temp[i];
	memcpy(input_block, v, 16);
	unsigned char output_temp[48] = { 0x00, };
	for (i = 0; i < 3; i++)
	{
		lea_encrypt(chaining_value, input_block, key);

		memcpy(output_temp + (i * 16), chaining_value, 16);
		memcpy(input_block, chaining_value, 16);
		memset(chaining_value, 0x00, 16);
	}
	memcpy(output, output_temp, 48);

	free(S);
	free(new_S);
}


/*내부갱신함수*/
void Update(STATE* state, unsigned char* input, unsigned int input_len)
{
	unsigned char key[32] = { 0x00, };
	memcpy(key, state->state_handle.Key, 32);
	unsigned char v[16] = { 0x00, };
	memcpy(v, state->state_handle.V, 16);
	unsigned char input_temp[48] = { 0x00, };
	memcpy(input_temp, input, 48);
	unsigned char chaining_temp[48] = { 0x00, };
	unsigned char output_temp[48] = { 0x00, };
	unsigned char output_block[16] = { 0x00, };
	unsigned char one[1] = { 0x01 };
	int i, j;

	for (i = 0; i < 3; i++)
	{
		SUM_of_one(v, 16, one, 1, v);
		lea_encrypt(output_block, v, key);
		memcpy(chaining_temp + i * 16, output_block, 16);
	}

	for (i = 0; i < 48; i++)
	{
		output_temp[i] = chaining_temp[i] ^ input_temp[i];
	}
	for (i = 0; i < 32; i++)
		state->state_handle.Key[i] = output_temp[i];
	for (i = 32; i < 48; i++)
		state->state_handle.V[i - 32] = output_temp[i];
}

/*외부갱신 함수*/
void Reseed_function(STATE* state, unsigned char* entropy, unsigned int entropy_len, unsigned char* additional, unsigned int additional_len)
{
	int i;
	unsigned char seed[48] = { 0x00, };
	unsigned char addition[48] = { 0x00, };
	unsigned char entro[48] = { 0x00, };

	if (state->state_control.df_flag == 1)
	{
		int len = entropy_len + additional_len;
		unsigned char* seed_material = (unsigned char*)calloc(len, sizeof(unsigned char));
		//seed_material = entropy || additional
		for (i = 0; i < entropy_len; i++)
			seed_material[i] = entropy[i];
		for (i = entropy_len; i < len; i++)
			seed_material[i] = additional[i - entropy_len];
		DF(state, seed_material, len, seed, 48);
		free(seed_material);
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
	Update(state, seed, 48);
	state->state_handle.reseed_counter = 1;

}

void Generator_usePR(STATE* state, unsigned char* entropy, unsigned int entropy_len, unsigned char* additional, unsigned int additional_len, unsigned char* perseudorandom)
{


	int i;
	unsigned char key[32] = { 0x00, };
	unsigned char v[16] = { 0x00, };
	unsigned char addition[48] = { 0x00, };
	unsigned char one[1] = { 0x01 };
	unsigned int add_len = additional_len;

	memcpy(key, state->state_handle.Key, 32);
	memcpy(v, state->state_handle.V, 16);

	/*외부갱신*/

	if (state->state_control.prediction_resisitance_flag == 1)
	{
		Reseed_function(state, entropy, entropy_len, additional, additional_len);


		additional_len = 0;
		additional = NULL;
	}

	if (additional != NULL)
	{
		if (state->state_control.df_flag == 1)
		{
			DF(state, additional, additional_len, addition, 48);
		}
		else if ((state->state_control.df_flag == 0) && (additional_len < 48))
		{
			memset(addition, 0x00, 48);
			memcpy(addition, additional, additional_len);
		}

		Update(state, addition, 48);
	}


	unsigned char output[16] = { 0x00, };
	unsigned char randombits[128] = { 0x00, };
	unsigned char bf_V[16] = { 0x00, };

	memcpy(key, state->state_handle.Key, 32);
	memcpy(v, state->state_handle.V, 16);

	/*출력생성*/
	for (i = 0; i < 8; i++)
	{
		memcpy(v, v, 16);
		SUM_of_one(v, 16, one, 1, v);
		lea_encrypt(output, v, key);
		memcpy(randombits + i * 16, output, 16);
	}

	memcpy(state->state_handle.V, v, 16);
	memcpy(state->state_handle.Key, key, 32);

	memcpy(perseudorandom, randombits, 128);

	/*내부갱신*/
	Update(state, addition, 48);
}

void Generator_noPR(STATE* state, unsigned char* additional, unsigned int additional_len, unsigned char* perseudorandom)
{
	//printf("[addition]\n");
	//for (int A = 0; A < additional_len; A++)
	//	printf("%02X ", additional[A]);
	//printf("\n");

	int i;
	unsigned char key[32] = { 0x00, };
	unsigned char v[16] = { 0x00, };
	unsigned char addition[48] = { 0x00, };
	unsigned char one[1] = { 0x01 };
	unsigned int add_len = additional_len;

	memcpy(key, state->state_handle.Key, 32);
	memcpy(v, state->state_handle.V, 16);

	/*외부갱신*/
	if (additional_len != 0)
	{
		if (state->state_control.df_flag == 1)
		{
			DF(state, additional, additional_len, addition, 48);
		}
		else if (state->state_control.df_flag == 0)
		{
			memcpy(addition, additional, additional_len);
		}

		Update(state, addition, 48);
	}

	unsigned char bf_V[16] = { 0x00, };
	unsigned char output[16] = { 0x00, };
	unsigned char randombits[128] = { 0x00, };

	memcpy(key, state->state_handle.Key, 32);
	memcpy(v, state->state_handle.V, 16);

	/*출력생성*/

	for (i = 0; i < 8; i++)
	{
	//	memcpy(bf_V, v, 16);
		SUM_of_one(v, 16,one, 1, v);
		lea_encrypt(output, v, key);
		memcpy(randombits + i * 16, output, 16);
	}

	memcpy(state->state_handle.V, v, 16);
	memcpy(perseudorandom, randombits, 128);

	//printf("마지막 내부갱신전 V\n");
	//for (int A = 0; A < 16; A++)
	//	printf("%02X ", state->state_handle.V[A]);
	//printf("\n");

	/*내부갱신*/
	Update(state, addition, 48);

	//printf("마지막 내부갱신후 V\n");
	//for (int A = 0; A < 16; A++)
	//	printf("%02X ", state->state_handle.V[A]);
	//printf("\n");

}


void usePR(STATE* state, unsigned char* entropy, unsigned int entropy_len, unsigned char* entropy1, unsigned int entropy1_len, unsigned char* entropy2, unsigned int entropy2_len, unsigned char* nonce, unsigned int nonce_len, unsigned char*  personalization, unsigned int personalization_len, unsigned char* additional1, unsigned int additional1_len, unsigned char* additional2, unsigned int additional2_len, unsigned char* returned_bits)
{
	unsigned char random1[128] = { 0x00, };
	unsigned char random2[128] = { 0x00, };

	Instantiate_Function(state, entropy, entropy_len, nonce, nonce_len, personalization, personalization_len);
	Generator_usePR(state, entropy1, entropy1_len, additional1, additional1_len, random1);
	Generator_usePR(state, entropy2, entropy2_len, additional2, additional2_len, random2);
	memcpy(returned_bits, random2, 128);
}

void noPR(STATE* state, unsigned char* entropy, unsigned int entropy_len, unsigned char* nonce, unsigned int nonce_len, unsigned char* personalization, unsigned int personalization_len, unsigned char* entropyreseed, unsigned int entropyreseed_len, unsigned char* additionalreseed, unsigned int additionalreseed_len, unsigned char* additional1, unsigned int additional1_len, unsigned char* additional2, unsigned int additional2_len, unsigned char* returned_bits)
{
	unsigned char random1[128] = { 0x00, };
	unsigned char random2[128] = { 0x00, };

	Instantiate_Function(state, entropy, entropy_len, nonce, nonce_len, personalization, personalization_len);
	Reseed_function(state, entropyreseed, entropyreseed_len, additionalreseed, additionalreseed_len);
	Generator_noPR(state, additional1, additional1_len, random1);
	Generator_noPR(state, additional2, additional2_len, random2);
	memcpy(returned_bits, random2, 128);
}