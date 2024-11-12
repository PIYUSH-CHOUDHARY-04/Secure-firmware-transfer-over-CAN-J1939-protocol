#include<stdio.h>
#include<stdint.h>

uint8_t gf_multiply(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    while (b > 0) {
        // If the lowest bit of b is set, add the current a to the result
        if (b & 1) {
            result ^= a; // Addition in GF(2^8) is an XOR operation
        }
        // Shift a to the left (equivalent to multiplication by x)
        uint8_t carry = a & 0x80; // Check if a has overflowed past 8 bits
        a <<= 1;
        // If there was an overflow, reduce modulo the irreducible polynomial
        if (carry) {
            a ^= 0x1b;
        }
        // Shift b to the right to process the next bit
        b >>= 1;
    }
    return result;
}

void main(void){

    uint8_t res=gf_multiply(2,247);
    printf("res : %d\n",res);
}
