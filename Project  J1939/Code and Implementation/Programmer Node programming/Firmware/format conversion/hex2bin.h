#ifndef __HEX2BIN_H
#define __HEX2BIN_H

/**
 * @brief Description of Intel .hex file or .hex records.
 *	  .hex file contains ASCII readable text charcacters encoding the entire firmware creation rules
 *	  grouped into a lot of structures called records each starting with 'colon (:)'.
 *	  Each record contains various fields and has structure as follow : 
 *		
 *	  [Record mark (:)]|[Data length]|[Address]|[Record type]|[Actual data]|[Checksum]
 *		1Byte		1Byte	    2Bytes	1Byte	   0-255 Bytes	  1Byte
 *
 *  	# Record mark (:) : every record starts with a colon (:) and typically each record is written on a new line (length = 1 byte)
 *	# Data length : this field holds the length of the data field i.e. how many bytes does this record have which can be written 
 *		        in flash or some other memory from where execution can be done, since the length of this field is 1 byte only
 *			thus the minimum data that a record can have is 0 bytes and maximum data that a record can have is 255 bytes.
 *			So, the minimum possible length of a record can be 6 Bytes and maximum possible record length can be 261 Bytes.
 *			(length = 1 byte)
 *	# Address : Tells the 16 bit address of the memory cells where the data contained into the record has to be copied/written/flashed. 
 *		    since this field has length of 2 bytes only, thus it can only address upto 64KB of address space, thus for systems running
 *		    on 32 bit architecture would cause problem in accessing the address beyond 64KB, this problem is taken care by the Record 
 *		    type byte. (length = 2 bytes)
 *	# Record type : This is one of the most crucial field of the entire record, this field basically defines what a record actually contains 
 *	   		and how it should be parsed by a bootloader or some external program, this field contains some possible values each of which 
 *		     	creates a correspondence to a predefined structure of the entire record.
 *				Record Type values : 
 *					->  '00' : Data Record				:: record format : [:]|[0x00-0xFF]|[16 bit addr]|[0x00]|[0-255 bytes]|[CheckSum]
 *					->  '0l' : End of File Record			:: record format : [:]|[0x00]|[16 bit addr but of no use here]|[0x01]|[0 byte of data]|[CheckSum]
 *					->  '02' : Extended Segment Address Record 	
 *					->  '03' : Start Segment Address Record
 *					->  '04' : Extended Linear Address Record	:: record format : [:]|[0x02]|[lower 16 bits, 0x00-0x00 because of no use in this record]|[0x04]|[upper 16 bits of address]|[CheckSum]
 *					->  '05' : Start Linear Address Record
 *			The remaining 3 values whose record format is not described are of no use of us thus ignored, you can refer to attached document for more details about "Intel hex records".
 *	  
 *
 *	# Actual data : This field actually holds the data or the entire data block with size specified in the Data length field to be written to the given address in address field of the record. 
 *			(length = 0-255 bytes)
 *	# CheckSum : A single byte checksum is appended with the record to make a complete record, CheckSum plays a crucial role in integrity verification for tempering of the incoming firmware. 
 *		     (length = 1 byte)
 *
 *	
 *	Still three problems are there...
 *	1.) How does the 32 bit addressing is tackled and what about 64 bit addressing ???
 *	2.) Calculating the checksum
 *	3.) Do we actually need the 'Type 04' record parsing ???
 *
 *	Sol.1. : The upper 16 bits causes the address to fall in extended range, thus the Record type for upper 16 bits is not marked as data record type but instead marked as 'Extended Linear Address Record'.
 *		 So, whenever the 'Type 04' record is written, this means upper 16 bits are fixed and subsequent 'Type 00' record will contain the lower 16 bits of the 32 bit address space, this allows flexibility
 *		 when all the required address space which needed to be accessed are not much far from each other i.e. falls under the same set which is created by fixing upper 16 bits.
 *		 This 'Type 04' is record is used at first time at the top of the .hex file i.e. the first record would be the 'Type 04' record for 32 bit architecture, then the remaining records will populate the flash.
 *		 The upper 16 bits acts as refrence to the 64KB address space, if one need to access the address out of this 64KB region, one can again call the 'Type 04' record, this can be proven to be useful in scenarios
 *		 when the desired memory extend pasts of 64KB region.
 *	Sol.2. : The CheckSum for records in .hex file is calculated as :
 *		 -> Add all the bytes (simple decimal addition of byte values) except the 'Record mark' and the 'CheckSum' itself i.e. add all the bytes of the fields 'Data length', 'Address', 'Record type' and 'Actual data'.
 *		 -> If the sum exceeds a byte width i.e. exceeds decimal 255, then truncate all upper bits so that only lower 8 bits are left.
 *		 -> Take complement of the truncated value i.e. take complement of the byte and add 1 (basically taking 2's complement of the byte.), and its the checksum.
 * 	Sol.3. : Since our goal is to translate the .hex records into the actual firmware layout which mimics the layout of .bin file thus we're typically converting a .hex file into .bin file, also the reason behind development 
 *		 of this tool is to help performing self-programming i.e. we just need to extract the actual firmware image and then flash it into the micro-controller's flash memory and then we'll trigger reset which will result
 *		 in execution of the the firmware directly from the flash memory, default and custom bootloader invocation depends on underlying hardware circuitry and the booting protocols, like on Arduino, the custom bootloader
 *		 is itself available on flash memory, thus got invoked everytime and then it checks for specific commands over some specified peripherals to perform firmware updates, and in case of STM32 micro-controllers, the 
 *		 default bootloader is present inside the system memory which is a dedicated flash memory for holding the bootloader's code, also, it provides the booting mode configuration like booting directly into the flash 
 *		 memory or booting into the system's memory which will result in default bootloader invocation which in turn results into hope for firmware update, if the device is directly booted into the flash memory, user 
 *		 firmware execution got started.
 *
 *
 *
 */


#include<stdio.h>
#include<stdint.h>




#define ARCH_8_BIT	0x08
#define ARCH_16_BIT	0x10
#define ARCH_32_BIT	0x20

#define __SYS_ARCH 	ARCH_32_BIT  /* Set as per your architecture. */


#if __SYS_ARCH == ARCH_8_BIT
/* for 8 bit architecture, Record types can only hold two values : 0x00 and 0x01 i.e. data record type and EOF record type. */
typedef struct{
		uint8_t curr_record; /* Max records can be 255 if each record at minimum holds 1 byte. */
} Info_8BitArch;
#endif /* __SYS_ARCH == ARCH_8_BIT */


#if __SYS_ARCH == ARCH_16_BIT
/* for 16 bit architecture, Record types can only hold two values : 0x00 and 0x01 i.e. data record type and EOF record type. */
typedef struct{
		uint16_t curr_record; /* Max records can be 2^16 if each record at minimum holds 1 byte. */
} Info_16BitArch;
#endif /* __SYS_ARCH == ARCH_16_BIT */


#if __SYS_ARCH == ARCH_32_BIT
/* for 32 bit architecture, Record types can only hold three values : 0x00, 0x01 and 0x04 i.e. data record type, EOF record type and Extended Linear address record type. */
typedef struct{
		uint32_t curr_record; /* Max records can be 2^32 if each record at minimum holds 1 byte. */
} Info_32BitArch;
#endif /* __SYS_ARCH == ARCH_32_BIT */


/*
	
	Each record can max hold the size of 255 data bytes + 6 bytes for other record fields.


*/






#endif /* __HEX2BIN_H */