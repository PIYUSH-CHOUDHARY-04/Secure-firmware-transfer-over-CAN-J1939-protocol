On node programming     :|
			 |
			 |: System Initialization
			 |	
			 |: Implementation of SPI communication
			 |
			 |: Implementation of J1939 and CAN 2.0B
			 |
			 |: Debugger

:: System Initialization :
		This involves setting up GPIO functionality for SPI communication; SPI functionality for communication between CAN controller and MCU, SD card and MCU; System clock and access to backup domain registers.


:: Implementation of SPI communication :
		This involves usage of HAL SPI routines to communicate with SD card and CAN controller, though CAN controller has its own API written on top of these HAL routines.


:: Implementation of J1939 and CAN 2.0B :
		This involves the usage of J1939 and CAN 2.0B routines to perform node to node communication for the purpose of firmware transfer.  			


:: Debugger :
		This defines a routine which is used to display bytes on 8 consecutive LEDs connected to GPIO pins of MCU, routine can be called in main function to keep the track of program flow.

