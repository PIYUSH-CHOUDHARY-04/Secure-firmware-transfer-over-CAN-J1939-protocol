#include"aes.h"
#include<stdio.h>

/**
 * --------------------------------------------------------------------------------------------------
 * File: aes.c
 * Description: This file contains definitions of routines used to encrypt and decrypt the specific input which are used to implement the AES algorithm.
 * Author: Piyush Choudhary
 * Date: Nov-4-2024
 * Refrences: http://csrc.nist.gov/archive/aes/rijndael/Rijndael-ammended.pdf#page=1 , https://en.wikipedia.org/wiki/Rijndael_S-box , https://en.wikipedia.org/wiki/Rijndael_MixColumns , 
 *            https://www.ibm.com/docs/en/zos/2.4.0?topic=rules-pkcs-padding-method
 * --------------------------------------------------------------------------------------------------
 */

/**
 * @brief Round constants (rcon) array 
 *        each of the element of this array will corresponds to a constant which is XORed with a word in key expansion.
 * rcon_i={1 if i=1 ; 2*rcon_i-1 if i>1 and rcon_i-1 < 0x80 ; (2*rcon_i-1) ^ 0x11b if i>1 and rcon_i-1 > 0x80} 
 * below is the direct table for it.
 */
uint8_t rcon[15]={0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d,0x9a};

/** 
 * =============================================================[SUBSTITUTION TRANSFORMATION]==================================================================================
 * @defgroup SUBSTITUTION_TRANSFORMATION substitution_transformation
 * @brief Substitution transformation , This transformation is one of the 4 key transformation used throughout the AES algorithm to encrypt and decrypt the input.
 *        Following are the important quantities related to the substitution transformation (also called 'subbyte' transformation)
 * @{
 */

/* Used for calculating forward substitution byte. */
/* The column is determined by the least significant nibble, and the row by the most significant nibble. For example, the value 0x9a is converted into 0xb8.  */
const uint8_t Forward_Sbox[256]={/*     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f     */
                                        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, /* 0x00 */
                                        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, /* 0x10 */
                                        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, /* 0x20 */
                                        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, /* 0x30 */
                                        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, /* 0x40 */
                                        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, /* 0x50 */
                                        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, /* 0x60 */
                                        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, /* 0x70 */
                                        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, /* 0x80 */
                                        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, /* 0x90 */
                                        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, /* 0xa0 */
                                        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, /* 0xb0 */
                                        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, /* 0xc0 */
                                        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, /* 0xd0 */
                                        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, /* 0xe0 */
                                        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16  /* 0xf0 */
                                    };

#if ROUTINE_SELECTOR == DECRY_ONLY || ROUTINE_SELECTOR == _ALL
/* Use for calculating inverse substitution byte. */
/* The column is determined by the least significant nibble, and the row by the most significant nibble. For example, the value 0xb8 is converted into 0x9a.  */
const uint8_t Inverse_Sbox[256]={/*     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f     */
                                        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, /* 0x00 */
                                        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, /* 0x10 */
                                        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, /* 0x20 */
                                        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, /* 0x30 */
                                        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, /* 0x40 */
                                        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, /* 0x50 */
                                        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, /* 0x60 */
                                        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, /* 0x70 */
                                        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, /* 0x80 */
                                        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, /* 0x90 */
                                        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, /* 0xa0 */
                                        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, /* 0xb0 */
                                        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, /* 0xc0 */
                                        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, /* 0xd0 */
                                        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, /* 0xe0 */
                                        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d  /* 0xf0 */
                                    };
#endif

/**
 * @brief Evalutes the forward 'Substitution transformation' for individual byte i.e. maps individual byte to its substitutional byte.      
 * @param uint8_t input_byte passes the byte which needs to be transformed.
 * @retval uint8_t returns the transformed byte.
 */
uint8_t ForwardSubByte(uint8_t input_byte) {
    /* For calculating the substitute byte for any inout byte, we uses the forward S box matrix, thu we need to calculate the roq and column number for that specific byte,
       The baisc rule is that 4 upper bits of the input bytes will be used to know the row number and column number is determined by lower 4 bits. 
    
       In the forward S-box  matrix, the postion of the substitution byte can be found by doing OR operation (basically doing product in binary for this case) of column number and row number, which is bsically
       the byte value itself,   
    */
   return Forward_Sbox[input_byte]; 
}

#if ROUTINE_SELECTOR == DECRY_ONLY || ROUTINE_SELECTOR == _ALL
/**
 * @brief Evalutes the inverse 'Substitution transformation' for individual byte i.e. maps individual byte to its substitutional byte.
 * @param uint8_t input_byte passes the byte which needs to be transformed.
 * @retval uint8_t returns the transformed byte.
 */
uint8_t InverseSubByte(uint8_t input_byte){
    /* similar to ForwardSubByte routine */
    return Inverse_Sbox[input_byte];
}
#endif

/**
 * @brief Evalutes the forward 'Substitution transformation' for the entire state array by looking at the forward S-box.
 * @param uint8_t* StateArray passes the address of the state array.
 * @retval void
 */
void ForwardSubstitutionTransformation(uint8_t* StateArray){
    for(uint8_t i=0;i<16;i++){
        StateArray[i]=ForwardSubByte(StateArray[i]);    
    }
}

#if ROUTINE_SELECTOR == DECRY_ONLY || ROUTINE_SELECTOR == _ALL
/**
 * @brief Evalutes the inverse 'Substitution transformation' for the entire state array by looking at the inverse S-box.
 * @param uint8_t* StateArray passes the address of the state array.
 * @retval void
 */
void InverseSubstitutionTransformation(uint8_t* StateArray){
    for(uint8_t i=0;i<16;i++){
        StateArray[i]=InverseSubByte(StateArray[i]);
    }
}
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
void AddRoundKeyTransformation(uint8_t* RoundKey, uint8_t* StateArray){
    for(uint8_t i=0;i<16;i++){
        StateArray[i]=((StateArray[i])^(RoundKey[i]));
    }
}

/**
 * @}
 * ===========================================================================================================================================================================
 */



/**
 * =============================================================[ROW SHIFTING TRANSFORMATION]===================================================================================
 * @defgroup SHIFT_ROW_TRANSFORMATION shift_row_transformation
 * @brief Objects for peforming row shifting transformation.
 * @{
 */

/**
 * @brief Performs rotational left shift for the uint8_t array of 4 members, this routine is specifically written for the sake of compactness of the library, thus limiting the
 *        count values in {1,2,3}, thus no 
 *        circulation in count value using modulo.
 * @param uint8_t* ptr passes the address of the 4 byte array which has to be left rotated by certain number.
 * @param uint8_t count passes the value by which left rotation has to be done i.e. count tells the bytes to skip while left rotation.
 * @retval void 
 */
void ROTL_4Bytes(uint8_t* ptr, uint8_t count){
    
    uint8_t swapper=0; /* used for swapping the byte values of 4 byte/word. */
    if(count%4==0 || count==0){
        return ;
    }
    
    for(uint8_t j=0;j<count;j++){
        swapper=ptr[0];
        for(uint8_t i=0;i<WORD-1;i++){
            ptr[i]=ptr[i+1];
        }
        ptr[WORD-1]=swapper;
    }
}

#if ROUTINE_SELECTOR == ENCRY_ONLY || ROUTINE_SELECTOR == _ALL
/**
 * @brief Performs the row shifting operation on each row, on row 0, no operation is performed, on row 1, left rotational shift by 1, on row 2, left rotational shift by 2, on row 3, 
 *        left rotational shift by 3.
 * @param uint8_t* StateArray passes the address of the state array on which row shifting transformation has to be performed.
 * @retval void
 */
void ForwardShiftRowTransformation(uint8_t* StateArray){
    /* First row remains as it is thus ommiting running loop over it. */
    for(uint8_t i=1;i<WORD;i++){
        ROTL_4Bytes(StateArray + (WORD)*i , i);    
    }
}
#endif

#if ROUTINE_SELECTOR == DECRY_ONLY || ROUTINE_SELECTOR == _ALL
/**
 * @brief Performs rotational right shift for the uint8_t array of 4 members.
 * @param uint8_t* ptr passes the address of the 4 byte array which has to be right rotated by certain number.
 * @param uint8_t count passes the value by which left rotation has to be done i.e. count tells the bytes to skip while left rotation.
 * @retval void
 */
void ROTR_4Bytes(uint8_t* ptr, uint8_t count){
    uint8_t swapper=0;
    if(count%4==0 || count==0){
        return ;
    }
    
    for(uint8_t j=0;j<count;j++){
        swapper=ptr[WORD-1];
        for(uint8_t i=WORD-1;i>0;i--){
            ptr[i]=ptr[i-1];
        }
        ptr[0]=swapper;    
    }
}

/**
 * @brief Performs the row shifting operation on each row, on row 0, no operation is performed, on row 1, right rotational shift by 1, on row 2, right rotational shift by 2, on row 3, 
 *        right rotational shift by 3.
 * @param uint8_t* StateArray passes the address of the state array on which row shifting transformation has to be performed.
 * @retval void 
 */
void InverseShiftRowTransformation(uint8_t* StateArray){
        for(uint8_t i=1;i<WORD;i++){
            ROTR_4Bytes(StateArray + (WORD)*i , i);
        }
}
#endif


/**
 * @}
 * =================================================================================================================================================================================
 */



/**
 * =============================================================[MIX COLUMN TRANSFORMATION]=========================================================================================
 * @defgroup MIX_COLUMN_TRANSFORMATION mix_column_transformation
 * @brief Objects for performing column mixing transformation.
 * @{
 */

#if ROUTINE_SELECTOR == ENCRY_ONLY || ROUTINE_SELECTOR == _ALL
/* Used to perform forward mix column transformation */
const uint8_t Forward_MixColumn[4][4]={
                                            {0x02, 0x03, 0x01, 0x01},
                                            {0x01, 0x02, 0x03, 0x01},
                                            {0x01, 0x01, 0x02, 0x03},
                                            {0x03, 0x01, 0x01, 0x02}
                                      };
#endif

#if ROUTINE_SELECTOR == DECRY_ONLY || ROUTINE_SELECTOR == _ALL
/* Used to perform inverse mix column transformation */
const uint8_t Inverse_MixColumn[4][4]={
                                            {0x0e, 0x0b, 0x0d, 0x09},
                                            {0x09, 0x0e, 0x0b, 0x0d},
                                            {0x0d, 0x09, 0x0e, 0x0b},
                                            {0x0b, 0x0d, 0x09, 0x0e}
                                      };
#endif


/**
 * @brief Performs multiplication of two bytes in GF(2^8) field.
 * @param uint8_t byte1 passes the value of byte1
 * @param uint8_t byte2 passes the value of byte2
 * @uint8_t returns the product of two bytes in galois field GF(2^8)
 */
uint8_t GF_MUL(uint8_t byte1, uint8_t byte2){
    /* we'll use the irreducible polynomial here but only the lower 1 byte i.e. 0x1B only */
    uint8_t result = 0;
    while (byte2 > 0) {
        // If the lowest bit of byte2 is set, add the current a to the result
        if (byte2 & 1) {
            result ^= byte1; // Addition in GF(2^8) is an XOR operation
        }
        // Shift byte1 to the left (equivalent to multiplication by x)
        uint8_t carry = byte1 & 0x80; // Check if a has overflowed past 8 bits
        byte1 <<= 1;
        // If there was an overflow, reduce modulo the irreducible polynomial
        if (carry) {
            byte1 ^= 0x1b;
        }
        // Shift b to the right to process the next bit
        byte2 >>= 1;
    }
    return result;
}

#if ROUTINE_SELECTOR == ENCRY_ONLY || ROUTINE_SELECTOR == _ALL
/**
 * @brief Performs forward Mix column transformation.
 * @param uint8_t* StateArray passes the address of the state array on which mix column transformation has to be carried out.
 * @retval void
 */
void ForwardMixColumnTransformation(uint8_t* StateArray){
/* External for loop for selecting the columns. */
    uint8_t col_vector[4];
   
    for(uint8_t col=0;col<WORD;col++){
        for(uint8_t i=0;i<WORD;i++){
    		col_vector[i] = GF_MUL(Forward_MixColumn[i][0], StateArray[0]) 
                          ^ GF_MUL(Forward_MixColumn[i][1], StateArray[4]) 
                          ^ GF_MUL(Forward_MixColumn[i][2], StateArray[8]) 
                          ^ GF_MUL(Forward_MixColumn[i][3], StateArray[12]);
        }
        
	    for(uint8_t j=0;j<WORD;j++){
		    StateArray[WORD*j]=col_vector[j];
	    }
	    StateArray++;	
	}
}
#endif

#if ROUTINE_SELECTOR == DECRY_ONLY || ROUTINE_SELECTOR == _ALL
/**
 * @brief Performs inverse Mix column transformation.
 * @param uint8_t* StateArray passes the address of the state array on which mix column transformation has to be carried out.
 * @retval void
 */
void InverseMixColumnTransformation(uint8_t* StateArray){/* External for loop for selecting the columns. */
    uint8_t col_vector[4];
   
    for(uint8_t col=0;col<WORD;col++){
        for(uint8_t i=0;i<WORD;i++){
    		col_vector[i] = GF_MUL(Inverse_MixColumn[i][0], StateArray[0]) 
                          ^ GF_MUL(Inverse_MixColumn[i][1], StateArray[4]) 
                          ^ GF_MUL(Inverse_MixColumn[i][2], StateArray[8]) 
                          ^ GF_MUL(Inverse_MixColumn[i][3], StateArray[12]);
        }
        
	    for(uint8_t j=0;j<WORD;j++){
		    StateArray[WORD*j]=col_vector[j];
	    }
	    StateArray++;	
	}
}
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
void AES_ExpandKey(uint8_t AES_Type, const uint8_t* key, uint8_t* ExpKey){
        /* Key expansion is done word by word since each round uses 1 word i.e. 4 bytes. */
        word* Word=(word*)ExpKey;
        uint8_t AES_ExpKey_WC=(7+AES_Type/4)*4;
    
        /* AES128 has 11 rounds in total, 1 initialization round and 12 rounds which are set of above transformations, thus the total expanded key size for this will be 11*4 = 44 words since each add round key transformation needs 4 words.
           Thus the uint8_t* ExpKey pointer must have 44*4 = 176 bytes free after it.         
         */
        
        /* AES192 has 13 rounds in total, 1 initialization round and 14 rounds which are set of above transformations, thus the total expanded key size for this will be 13*4 = 52 words since each add round key transformation needs 4 words.
           Thus the uint8_t* ExpKey pointer must have 52*4 = 208 bytes free after it.         
         */

        /* AES256 has 15 rounds in total, 1 initialization round and 16 rounds which are set of above transformations, thus the total expanded key size for this will be 15*4 = 60 words since each add round key transformation needs 4 words.
           Thus the uint8_t* ExpKey pointer must have 60*4 = 240 bytes free after it.         
         */
        
        for(uint8_t i=0;i<AES_ExpKey_WC;i++){
            if(i<(uint8_t)(AES_Type/WORD)){/* Key length in words, 4 words for AES128, 6 words for AES192, 8 words for AES256 */
                Word[i]=((word*)key)[i];
            }else
            if(i>=(uint8_t)(AES_Type/WORD) && i%(uint8_t)(AES_Type/WORD)==0){
                /* words( of ExpKey ) whose positions are integer multiple of (uint8_t)(AES_Type/WORD) will be calculated out using a sequence of steps  */
                /* step 1 : take Word[i-1] and rotate it left by 1 */
                Word[i]=Word[i-1];
                ROTL_4Bytes((uint8_t*)(&Word[i]), 1);
                
                /* step 2 : substituting each byte of the word with corresponding sub byte from S-box */
                for(uint8_t j=0;j<4;j++){
                    ((uint8_t*)(&Word[i]))[j]=ForwardSubByte(((uint8_t*)(&Word[i]))[j]);        
                }

                /* step 3 : XORing with round constant , 1st byte of the word will be XORed with the round constant and left 3 will be XORed with 0x00 (need not to do XOR for last 3 bytes since a^0x00=a) */
                ((uint8_t*)(&Word[i]))[0]^=rcon[i];   

                /* step 4 : XORing the current value of Word[i] with Word[i-(uint8_t)(AES_Type/WORD)] */
                for(uint8_t k=0;k<4;k++){
                    ((uint8_t*)(&Word[i]))[k]^=((uint8_t*)(&Word[i-(uint8_t)(AES_Type/WORD)]))[k];
                }
            }else{ /* i > (uint8_t)(AES_Type/WORD)  */
                for(uint8_t l=0;l<4;l++){
                    ((uint8_t*)(&Word[i]))[l]= ( ((uint8_t*)(&Word[i-1]))[l] ^ ((uint8_t*)(&Word[i-(uint8_t)(AES_Type/WORD)]))[l] );
                }
            }  
        }  
}

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
void AES_Encrypt(uint8_t AES_Type, uint8_t* PlainByteStream, uint32_t Size_PlainByteStream, const uint8_t* key, uint32_t* Size_EncryptedByteStream, uint8_t* IV){
    uint8_t AES_RC=(AES_Type/4)+6;
    uint8_t AES_ExpKey_WC=(AES_RC+1)*4; /* expanded key size in words  */
    
    /* Checking for padding possibility other than 16 bytes which are must to be appended as per PKCS#7. */
    
       /* additional padding needed. */
    if(Size_PlainByteStream%AES_BLOCKSIZE!=0){
    	for(uint8_t n=0;n<(AES_BLOCKSIZE - (Size_PlainByteStream % AES_BLOCKSIZE));n++){
            PlainByteStream[Size_PlainByteStream + n]=(AES_BLOCKSIZE - (Size_PlainByteStream % AES_BLOCKSIZE));
	        *Size_EncryptedByteStream = Size_PlainByteStream + (AES_BLOCKSIZE-(Size_PlainByteStream)%AES_BLOCKSIZE);
        }
    }else{
    	for(uint8_t n=0;n<AES_BLOCKSIZE;n++){
		    PlainByteStream[Size_PlainByteStream + n]=(0x10);
	    }
	    *Size_EncryptedByteStream = Size_PlainByteStream + AES_BLOCKSIZE;
    }

    
    /* checking whether IV is already placed at last 16 bytes of the allocated array or not, if not placed, then doing so */
    if(IV!=(PlainByteStream+(*Size_EncryptedByteStream))){
        for(uint8_t k=0;k<16;k++){
            (PlainByteStream+(*Size_EncryptedByteStream))[k]=IV[k];
        }
    }
    
    /* Padding added as per PKCS#7 and IV is also appended, now expanding key */
    uint8_t ExpKey[AES_ExpKey_WC*WORD];
    AES_ExpandKey(AES_Type, key, ExpKey); 

    
    /* ExpKey for AES128, size is 44 words or 176 bytes , 11 quadwords or 11 aes_blocks  */
    /* ExpKey for AES192, size is 52 words or 208 bytes , 13 quadwords or 13 aes_blocks  */
    /* ExpKey for AES256, size is 60 words or 240 bytes , 15 quadwords or 15 aes_blocks  */

    aes_block* quad1=(aes_block*)PlainByteStream;

    for(uint32_t i=0;i<((*Size_EncryptedByteStream)/AES_BLOCKSIZE);i++){ /* encrypting quadword by quadword or state array by state array */
        /* Befor starting the core AES algorithm, we'll first XOR the plaintext with the IV. */
        for(uint8_t m=0;m<16;m++){
            ((uint8_t*)quad1)[m]^=IV[m];
        }        
        /* CORE AES ENCRYPTION BEGIN. */

        /* Proceeding to Initialization round. */
        AddRoundKeyTransformation(ExpKey, (uint8_t*)quad1);

        /* Round 1 to round AES_RC-1 */
        for(uint8_t j=0;j<AES_RC-1;j++){
            /* substitute byte transformation. */
            ForwardSubstitutionTransformation((uint8_t*)quad1);
            /* shift row transformation */
            ForwardShiftRowTransformation((uint8_t*)quad1);
            /* mix column transformation */
            ForwardMixColumnTransformation((uint8_t*)quad1);
            /* add round key transformation */
            AddRoundKeyTransformation(ExpKey+AES_BLOCKSIZE*(j+1), (uint8_t*)quad1);
        }
    
        /* Round AES_RC-1  */
        ForwardSubstitutionTransformation((uint8_t*)quad1);
        ForwardShiftRowTransformation((uint8_t*)quad1);
        AddRoundKeyTransformation(ExpKey+AES_ExpKey_WC*WORD-AES_BLOCKSIZE, (uint8_t*)quad1);

        /* CORE AES ENCRYPTION END. */

        /* IV for next data block will be the cipher text of the previous data block. */
        IV=(uint8_t*)quad1;
        /* advancing quad1 pointer to point to next data block */
        quad1++;
    }  
}
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
void AES_Decrypt(uint8_t AES_Type, uint8_t* EncryptedByteStream, uint32_t Size_EncryptedByteStream, const uint8_t* key, uint32_t* Size_DecryptedByteStream){
    uint8_t AES_RC=(AES_Type/4)+6;
    uint8_t AES_ExpKey_WC=(AES_RC+1)*4; /* expanded key size in words  */

    uint8_t ExpKey[AES_ExpKey_WC*WORD];
    uint8_t* ExpKey_ptr=ExpKey;
    
    AES_ExpandKey(AES_Type, key, ExpKey_ptr); 

    /* ExpKey for AES128, size is 44 words or 176 bytes , 11 quadwords or 11 aes_blocks  */
    /* ExpKey for AES192, size is 52 words or 208 bytes , 13 quadwords or 13 aes_blocks  */
    /* ExpKey for AES256, size is 60 words or 240 bytes , 15 quadwords or 15 aes_blocks  */

    aes_block* quad1=(aes_block*)EncryptedByteStream;
    /* Allocating an IV Block */
    aes_block IV_block0 = *((aes_block*)(EncryptedByteStream+Size_EncryptedByteStream)); /* The IV for the first encrypted block will be whats appended by AES_Encrypt at the end of given input encrypted stream. */
    aes_block IV_block1 = *(quad1); /* Cipher text of block(i-1) will be IV for block(i), thus storing separately else after decryption of block(i-1), IV will be lost for block(i) */
    /* Since we know the size of ExpKey which is AES_ExpKey_WC*4 , thus we'll now move the ExpKey pointer to the end of the expanded key and then with the loop, we'll fall back to initial word */

    ExpKey_ptr+=(AES_ExpKey_WC*4);

    for(uint32_t i=0;i<Size_EncryptedByteStream/AES_BLOCKSIZE;i++){ /* decrypting quadword by quadword or state array by state array */
        /* AES CORE DECRYPTION BEGIN. */

        /* Proceeding to Initialization round. */
        AddRoundKeyTransformation(ExpKey_ptr-AES_BLOCKSIZE, (uint8_t*)quad1);

        /* Round 1 to Round 9 */
        for(uint8_t j=0;j<AES_RC-1;j++){
            /* Inverse row shifting transformation */
            InverseShiftRowTransformation((uint8_t*)quad1);
            /* Inverse byte substitution transformation */
            InverseSubstitutionTransformation((uint8_t*)quad1);
            /* add round key transformation */
            AddRoundKeyTransformation(ExpKey_ptr-AES_BLOCKSIZE*(j+2), (uint8_t*)quad1);
            /* Inverse mix column transformation */
            InverseMixColumnTransformation((uint8_t*)quad1);
        }
    
        /* Round AES_RC */
        InverseShiftRowTransformation((uint8_t*)quad1);
        InverseSubstitutionTransformation((uint8_t*)quad1);
        AddRoundKeyTransformation(ExpKey_ptr-(AES_ExpKey_WC*4), (uint8_t*)quad1);

        /* AES CORE DECRYTION END. */

        /* XORing with IV */
        for(uint8_t k=0;k<16;k++){
            ((uint8_t*)quad1)[k]^=((uint8_t*)(&IV_block0))[k];
        }
           
        /* Setting new IV for next block in IV_block0 */
        IV_block0=IV_block1;

        /* advancing quad1 pointer to point to next data block */
        quad1++;

        /* saving cipher of next block as IV of next to next block */
        IV_block1=*(quad1);
    }


    /* Encrypted data has been decrypted, now removing padding and populating the Size_DecryptedByteStream */
    *Size_DecryptedByteStream=Size_EncryptedByteStream-EncryptedByteStream[Size_EncryptedByteStream-1]; /* decrypted data length = cipher text length - padding, using PKCS#7, last byte value will tell the padding bytes. */
    for(uint8_t k=0;k<EncryptedByteStream[Size_EncryptedByteStream];k++){
        EncryptedByteStream[*Size_DecryptedByteStream+k]=0x00;  /* Nullifying all padding bytes */
    }
}
#endif

/**
 * @}
 */
