#ifndef __AES_H__
#define __AES_H__

/**
 * --------------------------------------------------------------------------------------------------
 * File: aes.h
 * Description: This file contains declaration of prototypes of routines and other useful objects
 * 	        which are used to implement the AES algorithm.
 * Author: Piyush Choudhary
 * Date: Nov-4-2024
 * Refrences: http://csrc.nist.gov/archive/aes/rijndael/Rijndael-ammended.pdf#page=1 , https://en.wikipedia.org/wiki/Rijndael_S-box , https://en.wikipedia.org/wiki/Rijndael_MixColumns
 * --------------------------------------------------------------------------------------------------
 */

/**
 * @brief Device identification macros
 */
#define OS_DEVICE           0x00
#define EMBEDDED_DEVICE     0x01

#define DEVICE_ID 0x00      /*[MODIFIABLE]*/

#if DEVICE_ID == OS_DEVICE
    #include<stdint.h>

#endif

/**
 * @brief Routine selector macros, used mainly on embedded system where if one need to include only encryption functionality thus excluding decryption stuff or vice-versa can help in saving memory.
 */
#define ENCRY_ONLY 0x01
#define DECRY_ONLY 0x02
#define _ALL ( ENCRY_ONLY | DECRY_ONLY )

#define ROUTINE_SELECTOR _ALL       /*[MODIFIABLE]*/

/* Irreducible polynomial for AES */
#define IRRD_POL 0x11B

/* WORD = 4 bytes */
#define WORD 4

/* Word structure to directly deal with words instead of individual bytes. Not used for static/dynamic memory allocation but instead used only for pointer typecasting. */
typedef struct {
    uint8_t byte[4];
} word;

/* aes_block structure to directly deal with state arrays instead on individua words or bytes. Not used for static/dynamic memory allocation but instead used for pointer typecasting. */
typedef struct {
    uint8_t quadword[16];
} aes_block;



/* Type of AES algorithm do not differs at these basic underlying transformation level instead the following table gives idea about it.
 *     ____________________________________________________________________________________
 *    |                  |        AES128       |        AES192       |        AES256       | 
 *    |------------------|---------------------|---------------------|---------------------|      
 *    | Key size         | 128 bits / 16 bytes | 192 bits / 24 bytes | 256 bits / 32 bytes |
 *    |                  | / 4 word            | / 4 word            | / 4 word            |
 *    |------------------|---------------------|---------------------|---------------------|
 *    | Plain text size  | 128 bits / 16 bytes | 128 bits / 16 bytes | 128 bits / 16 bytes | 
 *    |------------------|---------------------|---------------------|---------------------|
 *    | No. of rounds    |      10             |        12           |      14             | 
 *    |------------------|---------------------|---------------------|---------------------|
 *    | Round key size   | 128 bits / 16 bytes | 128 bits / 16 bytes | 128 bits / 16 bytes |
 *    |                  |  / 4 word           |  / 4 word           |  / 4 word           |
 *    |__________________|_____________________|_____________________|_____________________|
 *
 *      Their is no direct relation between key size and number of rounds, higher number of rounds offers more security, no strict formula is their to govern the round count depending on key size, but using above table,
 *      one can have the progression : No. of rounds = 6 + (key size in bits)/32 = 6 + (key size in bytes)/4
 *      Thus for higher AES algos like AES512, one can take rounds lowest value as 22.
 * 
 */


/**
 * @brief Macros to use specific AES algorithm i.e. once can use these macros to choose which AES algorithm one want to use out of AES128-CBC, AES192-CBC and AES256-CBC.
 *        "AES Type macros", represents the key size as well in bytes.
 */

#define AES128 0x10
#define AES192 0x18
#define AES256 0x20

/* AES blocksize in bytes, size of state array a well. */
#define AES_BLOCKSIZE 0x10

/** 
 * @brief Macros denoting the round count for each AES algorithm.
 *        Since there is no direct relation between round count and key size, but for making the function small and portable and to avoid adding more code lines like conditionals checks etc to execute specific code for specific AES
 *        algorithm, we uses the above formula since this relation will help us define a single routine for all AES algorithms just by depending on AES Type macros.
 */
#define AES128_RC 6 + AES128/4
#define AES192_RC 6 + AES192/4
#define AES256_RC 6 + AES256/4

/**
 * @brief Macros denoting the word count in expanded key of each AES algorithm.
 */
#define AES128_EXPKEY_WC (AES128_RC+1)*4
#define AES192_EXPKEY_WC (AES192_RC+1)*4
#define AES256_EXPKEY_WC (AES256_RC+1)*4




/** 
 * =============================================================[SUBSTITUTION TRANSFORMATION]==================================================================================
 * @defgroup SUBSTITUTION_TRANSFORMATION substitution_transformation
 * @brief Substitution transformation , This transformation is one of the 4 key transformation used throughout the AES algorithm to encrypt and decrypt the input.
 *        Following are the important quantities related to the substitution transformation (also called 'subbyte' transformation)
 * @{
 */


/**
 * @brief Evalutes the forward 'Substitution transformation' for individual byte i.e. maps individual byte to its substitutional byte.
 * @param uint8_t* input_byte passes the byte which needs to be transformed.
 * @retval uint8_t returns the transformed byte.
 */
uint8_t ForwardSubByte(uint8_t input_byte);

#if ROUTINE_SELECTOR == DECRY_ONLY || ROUTINE_SELECTOR == _ALL
/**
 * @brief Evalutes the inverse 'Substitution transformation' for individual byte i.e. maps individual byte to its substitutional byte.
 * @param uint8_t* input_byte passes the byte which needs to be transformed.
 * @retval uint8_t returns the transformed byte.
 */
uint8_t InverseSubByte(uint8_t input_byte);
#endif

/**
 * @brief Evalutes the forward 'Substitution transformation' for the entire state array by looking at the forward S-box.
 * @param uint8_t* StateArray passes the address of the state array.
 * @retval void
 */
void ForwardSubstitutionTransformation(uint8_t* StateArray);

#if ROUTINE_SELECTOR == DECRY_ONLY || ROUTINE_SELECTOR == _ALL
/**
 * @brief Evalutes the inverse 'Substitution transformation' for the entire state array by looking at the inverse S-box.
 * @param uint8_t* StateArray passes the address of the state array.
 * @retval void
 */
void InverseSubstitutionTransformation(uint8_t* StateArray);
#endif

/**
 * @}
 * ===========================================================================================================================================================================
 */



/**
 * =============================================================[ADD ROUND KEY TRANSFORMATION]==================================================================================
 * @defgroup ADD_ROUND_KEY_TRANSFORMATION add_round_key_transformation
 * @brief Objects for AddRoundKeyTransformation.
 * @{
 */

/**
 * @brief Add Round key transformation , This transformation performs just simple XOR operation between 'state array' and 4 words of expanded key.
 *        Add round key transformation is an 'involution' i.e. (a^b)^b = a
 * @param uint8_t* RoundKey passes the address of the 4 word round key to be XORed.
 * @param uint8_t* StateArray passes the address of the state array to be XORed with RoundKey.
 * @retval void 
 */
void AddRoundKeyTransformation(uint8_t* RoundKey, uint8_t* StateArray);

/**
 * @}
 * =============================================================================================================================================================================
 */



/**
 * =============================================================[ROW SHIFTING TRANSFORMATION]===================================================================================
 * @defgroup SHIFT_ROW_TRANSFORMATION shift_row_transformation
 * @brief Objects for peforming row shifting transformation.
 * @{
 */

/**
 * @brief Performs rotational left shift for the uint8_t array of 4 members.
 * @param uint8_t* ptr passes the address of the 4 byte array which has to be left rotated by certain number.
 * @param uint8_t count passes the value by which left rotation has to be done i.e. count tells the bytes to skip while left rotation.
 * @retval void 
 */
void ROTL_4Bytes(uint8_t* ptr, uint8_t count);

#if ROUTINE_SELECTOR == ENCRY_ONLY || ROUTINE_SELECTOR == _ALL
/**
 * @brief Performs the row shifting operation on each row, on row 0, no operation is performed, on row 1, left rotational shift by 1, on row 2, left rotational shift by 2, on row 3, left rotational shift by 3.
 * @param uint8_t* StateArray passes the address of the state array on which row shifting transformation has to be performed.
 * @retval void
 */
void ForwardShiftRowTransformation(uint8_t* StateArray);
#endif

#if ROUTINE_SELECTOR == DECRY_ONLY || ROUTINE_SELECTOR == _ALL
/**
 * @brief Performs rotational right shift for the uint8_t array of 4 members.
 * @param uint8_t* ptr passes the address of the 4 byte array which has to be right rotated by certain number.
 * @param uint8_t count passes the value by which left rotation has to be done i.e. count tells the bytes to skip while left rotation.
 * @retval void 
 */
void ROTR_4Bytes(uint8_t* ptr, uint8_t count);

/**
 * @brief Performs the row shifting operation on each row, on row 0, no operation is performed, on row 1, right rotational shift by 1, on row 2, right rotational shift by 2, on row 3, right rotational shift by 3.
 * @param uint8_t* StateArray passes the address of the state array on which row shifting transformation has to be performed.
 * @retval void
 */
void InverseShiftRowTransformation(uint8_t* StateArray);
#endif

/**
 * @}
 * =================================================================================================================================================================================
 */



/**
 * =============================================================[MIX COLUMN TRANSFORMATION]=========================================================================================
 * @defgroup MIX_COLUMN_TRANSFORMATION mix_column_transformation
 * @brief Objects for performing column mixing transformation.
 *        In Galois field GF(2^8), addition of two elements of the field is defined as bitwise XOR between those elements to make sure that the field is bound under addition, and multiplication between two
 *        field elements is defined as direct product of the elements if the product is in range [0, 255] and if exceeds, then needs to be reduced by XORing with 0x11B (irreducible polynomial for AES)
 * @{
 */

/**
 * @brief Performs multiplication of two bytes in GF(2^8) field.
 * @param uint8_t byte1 passes the value of byte1
 * @param uint8_t byte2 passes the value of byte2
 * @uint8_t returns the product of two bytes in galois field.
 */
uint8_t GF_MUL(uint8_t byte1, uint8_t byte2);

#if ROUTINE_SELECTOR == ENCRY_ONLY || ROUTINE_SELECTOR == _ALL
/**
 * @brief Performs forward Mix column transformation.
 * @param uint8_t* StateArray passes the address of the state array on which mix column transformation has to be carried out.
 * @retval void
 */
void ForwardMixColumnTransformation(uint8_t* StateArray);
#endif

#if ROUTINE_SELECTOR == DECRY_ONLY || ROUTINE_SELECTOR == _ALL
/**
 * @brief Performs inverse Mix column transformation.
 * @param uint8_t* StateArray passes the address of the state array on which mix column transformation has to be carried out.
 * @retval void
 */
void InverseMixColumnTransformation(uint8_t* StateArray);
#endif



/**
 * @}
 * =================================================================================================================================================================================
 */


/**
 * @defgroup KEY_EXPANSION key_expansion
 * @brief Routines for key expansion for each of the AES algorithm.
 * @{
 */

/**
 * @brief Performs the key expansion to perform encryption and decryption for AES.
 * @param uint8_t AES_Type tells the type of AES algorithm, see AES_Type macros in aes.h
 * @param const uint8_t* key passes the address of the key, routine will automatically read specific number of key bytes depending on AES_Type.
 * @param uint8_t ExpKey passes the address of the memory region where the expanded key will be store, it's programmers responsibilty to make sure the required space's availability at the given address.
 * @retval void
 */
void AES_ExpandKey(uint8_t AES_Type, const uint8_t* key, uint8_t* ExpKey);


/**
 * @}
 */

/**
 * @defgroup AES_MAIN aes_main
 * @brief Routines to perform encryption and decryption over a specified byte stream using specified key.
 * @{
 */

#if ROUTINE_SELECTOR == ENCRY_ONLY || ROUTINE_SELECTOR == _ALL
/**
 * @brief Encrypts a given byte stream of specific length with specific key via AES algorithm, it encrypts the plain data at the same memory location the data is present, thus original data will encrypted, user can access the encrypted
 *        data via the same PlainByteStream pointer.
 *        after encryption, the encrypted data will be at same memory location as that of plain data with the structure : [encrypted data]|[IV], this will save our computation power, if the IV is prepended, we need to first rightshift all
 *        data bytes by 16 bytes to make space for 16 bytes of IV, if we do the opposite, we just need to copy the IV behind cipher text. 
 *        before encryption, the data sequence looks like [plain data]|[padding]|[IV]
 * @param uint8_t AES_Type tell which AES algorithm to use.
 * @param uint8_t* PlainByteStream passes the address of the input data which has to be encrypted, but the programmer has to make sure that the static or dynamic array in which unencrypted data is stored has size atleast
 *        ( Size_ByteStream + 16 bytes IV + X bytes ) where X=((Size_ByteStream)%AES_BLOCKSIZE) bytes if input size is not integral multiple of AES_BLOCKSIZE else X = AES_BLOCKSIZE bytes , 
 *        this is because the library uses PKCS#7 padding technique and also the input length must be multiple of AES block size which is 16 bytes.
 * @param uint32_t Size_ByteStream passes the size of the input data, here limited to largest size of 2^32 bytes(4GB), can be increased by using 'uint64_t' instead of 'uint32_t'.
 * @param const uint8_t* key passes the address of the key, size of key is governed by the AES_Type.
 * @param uint32_t* Size_EncryptedByteStream passes the address of the variable where the size of the encrypted input will be populated by the routine.
 *        if Size_PlainByteStream%AES_BLOCKSIZE = 0 ==> Size_EncryptedByteStream = Size_PlainByteStream + AES_BLOCKSIZE
 *        else Size_EncryptedByteStream = Size_PlainByteStream + AES_BLOCKSIZE + (AES_BLOCKSIZE - Size_PlainByteStream%AES_BLOCKSIZE)
 * @param uint8_t* IV passes the address of the initialization vector, the programmer need to make sure that each time this routine is used, the IV must be different (produced using CPRNG/PRNG).
 *        for embedded systems, to save memory, one can by himself/herself put the IV at last 16 bytes of the array of size ( Size_ByteStream + 16 bytes IV + 16 byte padding + (Size_ByteStream-((Size_ByteStream)%16)) byte padding ) passed 
 *        to the routine. 
 * @retval void
 */
void AES_Encrypt(uint8_t AES_Type, uint8_t* PlainByteStream, uint32_t Size_PlainByteStream, const uint8_t* key, uint32_t* Size_EncryptedByteStream, uint8_t* IV);
#endif

#if ROUTINE_SELECTOR == DECRY_ONLY || ROUTINE_SELECTOR == _ALL
/**
 * @brief Decrypts a given encrypted byte stream of specific length with specific key via AES algorithms, automatically removes the padding and IV (IV of no use after decryption)
 * @param uint8_t* EncryptedByteStream passes the address of the input data which has to be decrypted, the length of the decrypted data will always be less than than size of encrypted input data due to removal of padding which was added 
 *        during the encryption.
 * @param uint32_t Size_EncryptedByteStream passes the size of the input data, here limited to largest size of 2^32 bytes(4GB), can be increased by using 'uint64_t' instead of 'uint32_t', user must pass the value populated by encryption 
 *        routine in its Size_EncryptedByteStream variable i.e. only cipher text size must be passed, no need to include 16 bytes in Size_EncryptedByteStream for appended IV, this routine will automatically take care of that.
 * @param const uint8_t* key passes the address of the key, size of key is governed by the AES_Type.
 * @param uint32_t* Size_DecryptedByteStream is used to retrieve the length of the original data after removal of padding which was encrypted.
 * @retval void
 */
void AES_Decrypt(uint8_t AES_Type, uint8_t* EncryptedByteStream, uint32_t Size_EncryptedByteStream, const uint8_t* key, uint32_t* Size_DecryptedByteStream);
#endif

/**
 * @}
 */

#endif /* __AES_H__ */
