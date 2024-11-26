we'll be doing pre-encryption of the firmware bin file with some specific key and IV using AES256-CBC
and then do HMAC calculation and appending, once that's done, the entire data will be written back to a file 
which will be directly parsed by the python program to generate the text file containing individual bytes 
in hex form separated by commas which in turn can be directly copied to the static arrays for testing purposes since in real scenarios, the firmware will be received in some chunks of 2KBs.