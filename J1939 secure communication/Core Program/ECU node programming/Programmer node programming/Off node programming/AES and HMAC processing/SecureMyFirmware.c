#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<string.h>

#include "aes.h"
#include "sha1.h"
#include "hmac.h"

#define HMAC_KEY_MAXLEN 0x100
#define FILE_RENAME_SECURED 0x08
#define FILE_RENAME_SECURED_STR "secured_"
#define MAX_PATH_LEN 200


uint8_t AES256CBC_KEY[AES256]={0};
uint8_t IV[AES_BLOCKSIZE]={0};
uint8_t HMAC_KEY[HMAC_KEY_MAXLEN]={0};	// nullifying bytes will help using this array with string.h routines since this will behave like C string (null-terminated string)
uint8_t HMAC_CODE[20]={0};

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


	// getting IV
	printf("Pass your IV path (maximum path length : 200 bytes) : ");
	scanf("%200s",path);
	FILE* fptr_iv=fopen(path,"rb");
	if(fptr_iv==NULL){
		printf("Error : Unable to find the specified file %s\n",path);
		return;
	}
	if((fread(IV,sizeof(uint8_t),AES_BLOCKSIZE,fptr_iv))!=AES_BLOCKSIZE){
		printf("Error : Unable to read the specified file %s\n",path);
		return;
	}
	fclose(fptr_iv);
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


	
	FILE* fptr_bin=fopen(argv[1],"rb");
	if(fptr_bin==NULL){
		printf("Error : Unable to open %s file.\n",argv[1]);
		return;
	}
	// getting file size.
	fseek(fptr_bin,0,SEEK_END);
	long size=ftell(fptr_bin);
	long firmware_size=size;
	rewind(fptr_bin);
	printf("Firmware size : %ld\n",size);

	/* Size of the data to be encrypted is known, now need to calculate the padding byte count and then adding space for IV */
	if((size%AES_BLOCKSIZE)==0){
		/* padding = 16 bytes */
		printf("Padding size : %d\n",AES_BLOCKSIZE);
		size+=(2*AES_BLOCKSIZE);
	}else{
		printf("Padding size : %ld\n",AES_BLOCKSIZE-(size%AES_BLOCKSIZE));
		size+=((2*AES_BLOCKSIZE)-(size%AES_BLOCKSIZE));
	}

	// Allocating memory for storing firmware file.
	uint8_t* ptr=(uint8_t*)malloc(sizeof(uint8_t)*size);
	printf("Reading firmware file...\n");
	if(fread(ptr, sizeof(uint8_t), firmware_size,fptr_bin)!=firmware_size){
		printf("Error : Unable to read from %s file\n",argv[1]);
		return;
	}
	fclose(fptr_bin);
	printf("Read completed, Encrypting the file...\n");
	uint32_t encrypted_firmware_size=0;
	AES_Encrypt(AES256,ptr,(uint32_t)firmware_size,AES256CBC_KEY,&encrypted_firmware_size,IV);
	printf("Encryption completed !\nEncrypted firmware size : %d\n",encrypted_firmware_size);
	/* Encrypted data with padding bytes and IV appended are in array pointed by "ptr" */

	/* File rename handling. */
	uint8_t* rename=(uint8_t*)malloc(sizeof(uint8_t)*(strlen(argv[1])+FILE_RENAME_SECURED+1)); // +1 for null terminator.
	memcpy(rename,FILE_RENAME_SECURED_STR,FILE_RENAME_SECURED);
	memcpy(rename+FILE_RENAME_SECURED,argv[1],strlen(argv[1]));
	rename[FILE_RENAME_SECURED+strlen(argv[1])]='\0';

	/* opening a file to write the encrypted data  */
	FILE* fptr_encr=fopen(rename,"wb");
	if(fptr_encr==NULL){
		printf("Error : Unable to create new file %s\n",rename);
		return;
	}

	if(fwrite(ptr,sizeof(uint8_t),size,fptr_encr)!=size){
		printf("Error : Unable to write to %s\n",rename);
		return;
	}
	
	printf("Computing HMAC code...\n");
	hmac_sha1(HMAC_KEY, (uint32_t)strlen(HMAC_KEY), ptr, size, HMAC_CODE);
	if(fwrite(HMAC_CODE, sizeof(uint8_t), HMAC_SHA1_DIGEST_SIZE, fptr_encr)!=HMAC_SHA1_DIGEST_SIZE){
		printf("Error : Unable to write to %s file\n",rename);
		return;
	}
	printf("File secured.\n");
	fclose(fptr_encr);
	free(rename);
	free(ptr);
}
