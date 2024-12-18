Receiver node programming      :|
				|
				|: Out factory fist update
				|
				|: Subsequent updates over CAN-J1939
				|
				|: Debugger



:: Out factory first update :
		This involves updating the MCU firmware for first time via power machines (x86/x86_64/ARM) to create specific flash layout and uploading the custom bootloader and firmware for handling subsequent firmware updates over
		CAN-J1939 offering resistance against receiver node power failure/reset during communication and flashing via backup domain, thus resumed communication/firmware update.

:: Subsequent updates over CAN-J1939 :
		Involves writing receiver firmware with communication and update functionalities, like implementation of J1939 and CAN protocol, security implementations which includes AES and HMAC algorithms.


:: Debugger :
		This defines a routine which is used to display bytes on 8 consecutive LEDs connected to GPIO pins of MCU, routine can be called in main function to keep the track of program flow.
		It's definition will be defined in custom bootloader's routine collection, thus the firmware can access it.