Subsequent updates over CAN-J1939	:|
					 |
					 |: System Initialization
					 | 
					 |: Implementation of SPI protocol
					 |
					 |: Implementation of J1939 and CAN 2.0B
					 |		
					 |: AES and HMAC processing
					 |
					 |: Firmware update routines



:: System Initialization :
		Initialization of GPIO pins as SPI interface, all other initializations will be taken care of by custom bootloader.
		

:: Implementation of SPI protocol :
		This will involve setting up SPI for communicating with CAN controller. 


:: Implementation of J1939 and CAN 2.0B :
		This involves the usage of CAN and J1939 routines to ensure node to node communication.


:: AES and HMAC processing :
		This involves the HMAC integrity check and AES decryption of the received firmware.


:: Firmware update routines :
		Includes the definition of the firmware update routines offering resistance against power failures/resets.