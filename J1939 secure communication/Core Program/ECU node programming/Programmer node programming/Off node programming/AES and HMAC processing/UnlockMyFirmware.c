#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<string.h>

#include "aes.h"
#include "sha1.h"
#include "hmac.h"

#define HMAC_KEY_MAXLEN 0x100
#define FILE_RENAME_UNLOCKED 0x09
#define FILE_RENAME_UNLOCKED_STR "unlocked_"
#define MAX_PATH_LEN 200


uint8_t AES256CBC_KEY[AES256]={0};
uint8_t HMAC_KEY[HMAC_KEY_MAXLEN]={0};	// nullifying bytes will help using this array with string.h routines since this will behave like C string (null-terminated string)
uint8_t HMAC_CODE[HMAC_SHA1_DIGEST_SIZE]={0};

uint8_t path[MAX_PATH_LEN]={0};


void main(int argc, char** argv){ // Encrypts only one file at a time.
	// getting AES256-CBC key.
	printf("Pass your AES256-CBC key path (maximum path length : 200 bytes) : ");
	scanf("%200s",path);
	FILE* fptr_aes=fopen(path,"rb");
	if(fptr_aes==NULL){
		printf("Error : Unable to find the specified file %s\n",path);
		return;
	}	
	if((fread(AES256CBC_KEY,sizeof(uint8_t),AES256,fptr_aes))!=AES256){
		printf("Error : Unable to read the specified file %s\n",path);
		return;
	}
	fclose(fptr_aes);
	memset(path,0,MAX_PATH_LEN);

	//getting HMAC key
	printf("Pass your HMAC key path (maximum path length : 200 bytes) : ");
	scanf("%200s",path);
	FILE* fptr_hmac=fopen(path,"rb");
	if(fptr_hmac==NULL){
		printf("Error : Unable to find the specified file %s\n",path);
		return;
	}
	fseek(fptr_hmac,0,SEEK_END);
	long hmac_size=ftell(fptr_hmac);
	rewind(fptr_hmac);
	if(fread(HMAC_CODE,sizeof(uint8_t),hmac_size,fptr_hmac)!=hmac_size){
		printf("Error : Unable to read the specified file %s\n",path);
		return;
	}
	fclose(fptr_hmac);

	// opening secured firmware file.
	FILE* fptr_encr=fopen(argv[1],"rb");
	if(fptr_encr==NULL){
		printf("Error : Unable to open the specified file %s\n",argv[1]);
		return;
	}

	fseek(fptr_encr,0,SEEK_END);
	long file_size=ftell(fptr_encr);
	rewind(fptr_encr);
	printf("File size : %ld\n",file_size);
	printf("Allocating memory for secured firmware file...\n");
	uint8_t* ptr=(uint8_t*)malloc(sizeof(uint8_t)*file_size);
	printf("Allocated addr : %p\n",ptr);
	if(fread(ptr,sizeof(uint8_t),file_size,fptr_encr)!=file_size){
		printf("Error : Unable to read the firmware file.\n");
		return;
	}	
	
	printf("Computing HMAC code...\n");
	hmac_sha1(HMAC_KEY, (uint32_t)strlen(HMAC_KEY), ptr, file_size-HMAC_SHA1_DIGEST_SIZE, HMAC_CODE);
	
	printf("Verifying firmware integrity...\n");
	if(strncmp(HMAC_CODE, ptr+file_size-HMAC_SHA1_DIGEST_SIZE, HMAC_SHA1_DIGEST_SIZE)!=0){
		printf("Firmware is tampered, integrity verification failed.\n");
	}

	printf("Decrypting...\n");
	uint32_t decrypted_firmware_size=0;
	AES_Decrypt(AES256, ptr, file_size-HMAC_SHA1_DIGEST_SIZE-AES_BLOCKSIZE, AES256CBC_KEY, &decrypted_firmware_size);
	
	printf("Decrypted firmware size : %d\n",decrypted_firmware_size);

	// rename handling for the file.
	char* rename=(char*)malloc(sizeof(char)*(strlen(argv[1])+FILE_RENAME_UNLOCKED+1));
	memcpy(rename, FILE_RENAME_UNLOCKED_STR, FILE_RENAME_UNLOCKED);
	memcpy(rename+FILE_RENAME_UNLOCKED, argv[1], strlen(argv[1]));
	rename[FILE_RENAME_UNLOCKED+strlen(argv[1])]='\0';

	FILE* fptr_unlock = fopen(rename,"wb");
	if(fwrite(ptr, sizeof(uint8_t), decrypted_firmware_size, fptr_unlock)!=decrypted_firmware_size){
		printf("Error : Unable to write to %s file.\n",rename);
		return;
	}


	printf("firmware unlocked, file name : %s\n",rename);
	free(rename);
	fclose(fptr_unlock);
	



}
