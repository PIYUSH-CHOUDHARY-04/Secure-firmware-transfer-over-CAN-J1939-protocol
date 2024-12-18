Developing a C program which will use the AES-CBC and HMAC library source code to encrypt and secure a firmware file (.bin format) with AES256-CBC and HMAC respectively.
Since the default behavior of the AES-CBC encryption algorithm is to append the IV behind the encrypted data, thus the program will do HMAC computation of encrypted data and of IV appended to it as well.
