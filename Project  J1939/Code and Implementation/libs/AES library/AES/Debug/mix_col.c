#include<stdio.h>
#include<stdint.h>
#define WORD 4



const uint8_t Forward_MixColumn[4][4]={
                                            {0x02, 0x03, 0x01, 0x01},
                                            {0x01, 0x02, 0x03, 0x01},
                                            {0x01, 0x01, 0x02, 0x03},
                                            {0x03, 0x01, 0x01, 0x02}
                                      };

const uint8_t Inverse_MixColumn[4][4]={
                                            {0x0e, 0x0b, 0x0d, 0x09},
                                            {0x09, 0x0e, 0x0b, 0x0d},
                                            {0x0d, 0x09, 0x0e, 0x0b},
                                            {0x0b, 0x0d, 0x09, 0x0e}
                                      };

uint8_t GF_MUL(uint8_t byte1, uint8_t byte2){
    /* we'll use the irreducible polynomial here but only the lower 1 byte i.e. 0x1B only */
    uint8_t b1=byte1;
    uint8_t b2=byte2;
    uint8_t result = 0;
    while (byte2 > 0) {
        // If the lowest bit of b is set, add the current a to the result
        if (byte2 & 1) {
            result ^= byte1; // Addition in GF(2^8) is an XOR operation
        }
        // Shift a to the left (equivalent to multiplication by x)
        uint8_t carry = byte1 & 0x80; // Check if a has overflowed past 8 bits
        byte1 <<= 1;
        // If there was an overflow, reduce modulo the irreducible polynomial
        if (carry) {
            byte1 ^= 0x1b;
        }
        // Shift b to the right to process the next bit
        byte2 >>= 1;
    }
    printf("mul byte1 %u  byte2 %u :%u\n",b1,b2,result);    
    return result;
    
}

void ForwardMixColumnTransformation(uint8_t* StateArray){
    /* External for loop for selecting the columns. */
    uint8_t* ptr=StateArray;
    uint32_t temp=0;
    printf("initial StateArray pointer : %p\n",StateArray);
    uint8_t col_vector[4];
   
    for(uint8_t col=0;col<WORD;col++){
        
	printf("StateArray[0] : %u at col : %u\n",StateArray[0],col);
	printf("StateArray pointer : %p\n",StateArray);
        for(uint8_t i=0;i<WORD;i++){
		printf("StateArray[%d] : %u at col : %u and i : %u\n",WORD*i,StateArray[WORD*i],col,i);
		printf("StateArray pointer with i : %p\n",StateArray);
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
    for(uint8_t j=0;j<16;j++){
    	printf("mixcol(d) state byte[%d] : StateArray[%d]\n",j,ptr[j] );
    }
}

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

uint8_t StateArray[17]={24,4,147,50,
                        24,111,99,173,
                        59,226,38,165,
                        226,162,197,130,
                        '\0'
                        };




void main(void){

    for(uint8_t i=0;i<16;i++){
        printf("State array [%d] : %d\n",i,StateArray[i]);
    }
    ForwardMixColumnTransformation(StateArray);
    printf("Transformation done!");

    for(uint8_t i=0;i<16;i++){
        printf("State array [%d] : %d\n",i,StateArray[i]);
    }
    InverseMixColumnTransformation(StateArray);
    printf("Inverse transformation done!");
    for(uint8_t i=0;i<16;i++){
        printf("State array [%d] : %d\n",i,StateArray[i]);
    }

}











