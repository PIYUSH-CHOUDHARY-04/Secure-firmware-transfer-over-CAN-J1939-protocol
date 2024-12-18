Out factory first update       :|
				|
				|: Custom bootloader
				|
				|: Firmware on bootloader reference



:: Custom bootloader :
		Development of a custom bootloader which will offer the resistance against unpredictable power failures/resets thus allows system state recovery in conditions of power failure during 
		firmware updates. 
		This involves setting up system clock, GPIO pins for debugger, SPI interface for communicating with SD card.



:: Firmware on bootloader reference :
		Development of the very first firmware which will be flashed onto the receiver node after flashing bootloader, this will bind up all the communication protocol stacks like CAN-J1939 etc.