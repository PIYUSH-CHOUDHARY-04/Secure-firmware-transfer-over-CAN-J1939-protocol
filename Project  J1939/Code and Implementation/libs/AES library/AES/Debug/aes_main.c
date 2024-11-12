
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
        
        /* AES128 has 13 rounds in total, 1 initialization round and 14 rounds which are set of above transformations, thus the total expanded key size for this will be 13*4 = 52 words since each add round key transformation needs 4 words.
           Thus the uint8_t* ExpKey pointer must have 52*4 = 208 bytes free after it.         
         */

        /* AES128 has 15 rounds in total, 1 initialization round and 16 rounds which are set of above transformations, thus the total expanded key size for this will be 15*4 = 60 words since each add round key transformation needs 4 words.
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
                ((uint8_t*)(&Word[i]))[0]^=rcon[(i/4) - 1];   

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
 * @brief Encrypts a given byte stream of specific length with specific key via AES algorithm, it encrypts the plain data at the same memory location the data is present, thus original data will encrypted, user can access the encrypted
 *        data via the same PlainByteStream pointer.
 *        after encryption, the encrypted data will be at same memory location as that of plain data with the structure : [encrypted data]|[IV], this will save our computation power, if the IV is prepended, we need to first rightshift all
 *        data bytes by 16 bytes to make space for 16 bytes of IV, if we do the opposite, we just need to copy the IV behind cipher text. 
 *        before encryption, the data sequence looks like [plain data]|[padding]|[IV]
 * @param uint8_t AES_Type tell which AES algorithm to use.
 * @param const uint8_t* ByteStream passes the address of the input data which has to be encrypted, but the programmer has to make sure that the static or dynamic array in which unencrypted data is stored has size atleast
 *        ( Size_ByteStream + 16 bytes IV + 16 byte padding + (Size_ByteStream-((Size_ByteStream)%16)) byte padding ), this is because the library uses PKCS#7 padding technique and also the input length must be multiple of AES block size 
 *        which is 16 bytes.
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
    if(Size_PlainByteStream % AES_BLOCKSIZE!=0){
        /* additional padding needed. */
        for(uint8_t n=0;n<(AES_BLOCKSIZE - (Size_PlainByteStream % AES_BLOCKSIZE)) + AES_BLOCKSIZE;n++){
            PlainByteStream[Size_PlainByteStream + n]=(AES_BLOCKSIZE + (AES_BLOCKSIZE - (Size_PlainByteStream % AES_BLOCKSIZE)));
        }
    }

    /* populating Size_EncryptByteStream */
    *Size_EncryptedByteStream = Size_PlainByteStream + AES_BLOCKSIZE + (AES_BLOCKSIZE - Size_PlainByteStream%AES_BLOCKSIZE);

    
    /* checking whether IV is already placed at last 16 bytes of the allocated array or not, if not placed, then doing so */
    if(IV!=(PlainByteStream+Size_EncryptedByteStream)){
        for(uint8_t k=0;k<16;k++){
            (PlainByteStream+(*Size_EncryptedByteStream))[k]=IV[k];
        }
    }

    
    /* Padding added as per PKCS#7 and IV is also appended, now expanding key */
    uint8_t ExpKey[AES_ExpKey_WC*WORD]={0};
    AES_ExpandKey(key, ExpKey); 
    
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
            AddRoundKeyTransformation(ExpKey+WORD*(j+1), (uint8_t*)quad1);
        }
    
        /* Round AES_RC-1  */
        ForwardSubstitutionTransformation((uint8_t*)quad1);
        ForwardShiftRowTransformation((uint8_t*)quad1);
        AddRoundKeyTransformation(ExpKey+AES_ExpKey_WC-AES_BLOCKSIZE, (uint8_t*)quad1);

        /* CORE AES ENCRYPTION END. */

        /* IV for next data block will be the cipher text of the previous data block. */
        IV=(uint8_t*)quad1;
        /* advancing quad1 pointer to point to next data block */
        quad1++;
    }  
}






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

    uint8_t ExpKey[AES_ExpKey_WC*WORD]={0};
    uint8_t* ExpKey_ptr=ExpKey;
    AES_ExpandKey(key, ExpKey_ptr); 

    /* ExpKey for AES128, size is 44 words or 176 bytes , 11 quadwords or 11 aes_blocks  */
    /* ExpKey for AES192, size is 52 words or 208 bytes , 13 quadwords or 13 aes_blocks  */
    /* ExpKey for AES256, size is 60 words or 240 bytes , 15 quadwords or 15 aes_blocks  */

    aes_block* quad1=(aes_block*)EncryptedByteStream;
    /* Allocating an IV Block */
    aes_block IV_block0 = *(EncryptedByteStream+Size_EncryptedByteStream); /* The IV for the first encrypted block will be whats appended by AES_Encrypt at the end of given input encrypted stream. */
    aes_block IV_block1 = *(quad1); /* Cipher text of block(i-1) will be IV for block(i), thus storing separately else after decryption of block(i-1), IV will be lost for block(i) */
    /* Since we know the size of ExpKey which is AES_ExpKey_WC*4 , thus we'll now move the ExpKey pointer to the end of the expanded key and then with the loop, we'll fall back to initial word */
    ExpKey_ptr+=(AES_ExpKey_WC*4);

    for(uint32_t i=0;i<Size_EncryptedByteStream/AES_BLOCKSIZE;i++){ /* encrypting quadword by quadword or state array by state array */

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
        AddRoundKeyTransformation(ExpKey_ptr-(AES128_WC*4), (uint8_t*)quad1);

        /* AES CORE DECRYTION END. */

        /* XORing with IV */
        for(uint8_t k=0;k<16;k++){
            ((uint8_t*)quad1)[k]^=((uint8_t*)(&IV_block0))[k];
        }
    
        /* Setting new IV for next block in IV_block0 */
        IV_block0=IV_block1;

        /* advacing quad1 pointer to point to next data block */
        quad1++;

        /* saving cipher of next block as IV of next to next block */
        IV_block1=*(quad1);
    }

    /* Encrypted data has been decrypted, now removing padding and populating the Size_DecryptedByteStream */
    *Size_DecryptedByteStream=Size_EncryptedByteStream-EncryptedByteStream[Size_EncryptedByteStream]; /* decrypted data length = cipher text length - padding, using PKCS#7, last byte value will tell the padding bytes. */
    for(uint8_t k=0;k<EncryptedByteStream[Size_EncryptedByteStream];k++){
        EncryptedByteStream[*Size_DecryptedByteStream+k]=0x00;  /* Nullifying all padding bytes */
    }
}

