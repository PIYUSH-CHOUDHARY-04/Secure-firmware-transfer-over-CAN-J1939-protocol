#include<stdio.h>
#include"aes.h"

uint8_t PlainByteStream[49]="PiyushChoudhary.\0";
uint8_t Decrypted_data[49]={0};
const uint8_t key[17]="0123456789@#$<>;\0";

uint32_t Size_EncryptedByteStream=0;
uint32_t Size_DecryptedByteStream=0;
uint32_t Size_PlainByteStream=16;

uint8_t IV[17]="This_is_temp_IV.\0";

void main(void){
    setvbuf(stdout, NULL, _IONBF, 0);

	printf("__AES128__\n");
    ForwardSubByte(52);
	printf("plain data : %s\n", PlainByteStream);
	printf("key : %s\n", key);
	printf("Input IV : %s\n",IV);
	AES_Encrypt(AES128, PlainByteStream, Size_PlainByteStream, key, &Size_EncryptedByteStream, IV);
	PlainByteStream[48]='\0';
	printf("encrypted data : %s\n", PlainByteStream);
	
	AES_Decrypt(AES128,PlainByteStream,Size_EncryptedByteStream,key,&Size_DecryptedByteStream);
	printf("decrypted text : %s\n",PlainByteStream);


}
