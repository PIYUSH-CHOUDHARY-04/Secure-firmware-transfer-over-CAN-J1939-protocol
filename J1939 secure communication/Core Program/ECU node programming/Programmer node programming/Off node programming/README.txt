Out node programming   :|
			|
			|: AES and HMAC processing
			|
			|: dd utility writing



:: AES and HMAC processing :
		firmware will be encrypted on out of network machine to offload the security implementation overhead from programmer node.
        Description : Writing a C program which will encrypt the given firmware with AES256-CBC and append its HMAC code, the IV(appended with the encrypted firmware) is also included in HMAC calculations. 
                      this will produce a secured firmware file.


:: dd utility usage :
		This utility will write the encrypted firmware to SD card in RAW binary form without any File System.
        Description : Writing a C program for linux which uses "dd" utility to write to the data flash/SD card









