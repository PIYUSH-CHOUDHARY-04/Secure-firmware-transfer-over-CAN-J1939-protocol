#include<stdio.h>
#include<stdint.h>
#define WORD 4
/**
 * @brief Performs rotational left shift for the uint8_t array of 4 members, this routine is specifically written for the sake of compactness of the library, thus limiting the count values in {1,2,3}, thus no 
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

/**
 * @brief Performs the row shifting operation on each row, on row 0, no operation is performed, on row 1, left rotational shift by 1, on row 2, left rotational shift by 2, on row 3, left rotational shift by 3.
 * @param uint8_t* StateArray passes the address of the state array on which row shifting transformation has to be performed.
 * @retval void
 */
void ForwardShiftRowTransformation(uint8_t* StateArray){
    /* First row remains as it is thus ommiting running loop over it. */
    for(uint8_t i=1;i<WORD;i++){
        ROTL_4Bytes(StateArray + (WORD)*i , i);    
    }
}

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
 * @brief Performs the row shifting operation on each row, on row 0, no operation is performed, on row 1, right rotational shift by 1, on row 2, right rotational shift by 2, on row 3, right rotational shift by 3.
 * @param uint8_t* StateArray passes the address of the state array on which row shifting transformation has to be performed.
 * @retval void 
 */
void InverseShiftRowTransformation(uint8_t* StateArray){
        for(uint8_t i=1;i<WORD;i++){
            ROTR_4Bytes(StateArray + (WORD)*i , i);
        }
}


uint8_t StateArray[17]={
                        45,5,61,81,
                        142,103,104,152,
                        1,206,240,8,
                        203,74,134,236,'\0'
                        };

void main(void){

    for(uint8_t i=0;i<16;i++){
        printf("State array [%d] : %d\n",i,StateArray[i]);
    }
    ForwardShiftRowTransformation(StateArray);
    printf("Transformation done!");

    for(uint8_t i=0;i<16;i++){
        printf("State array [%d] : %d\n",i,StateArray[i]);
    }
    InverseShiftRowTransformation(StateArray);
    printf("Inverse transformation done!");
    for(uint8_t i=0;i<16;i++){
        printf("State array [%d] : %d\n",i,StateArray[i]);
    }

}
