#ifndef __FLASH_PROG_H
#define __FLASH_PROG_H


#include<stm32f4xx_hal_flash.h>
#include<stm32f4xx_hal_flash_ex.h>

/**
 *  This is a library written on top of STM32 HAL drivers, this library mainly targets the microprocessors of type STM32F4xx.
 */

/**
 *          ---------------------------------------------
 *              Purpose of writing this routine
 *          ---------------------------------------------
 *  This routine performs the self programming of the MCU (STM32F4xx more specifically, but similar underlying HAL routines for other MCU's can be called instead while working with some other MCU as well.),
 *  being more specific, this routine is designed to update/write the firmware into the flash via SRAM i.e. firmware data stored in SRAM which may be an aftercase after receiving the firmware data over some
 *  communication protocol like USB/UART/SPI etc.
 *  A linker file is also given with this library which is must to be used during source code compilation since the firmware update routine and related routines must be copied into the SRAM since flash won't be 
 *  available for read operations during write operations, if the programmer has decided to not use the the attached linker script, then he/she need to manually copy the flashing related routines to the SRAM
 *  and mark the region of SRAM as executable if not marked by default.
 *  For marking the SRAM region to be executable, you need to interact with the MPU(Memory Protection Unit) of the microprocessor.
 *
 */
/**
 * To use this library, one need to make sure that HAL library is initialized and all HAL drivers are included in the compilation, user need not to worry if he/she is using STM32CubeIDE with STM32MX.
 */
 

/**
 * Flash operation depends on the applied voltage to the microprocessor, the flash performance in context of read/write/erase increases on increasing the applied voltage.
 * Operating voltage of the microprocessor can be known by looking at the data-sheet, following table is generally followed but can be modified based on the type of flash and microprocessor used.
 *   _______________________________________________________________________________________________
 *  |  Wait states (WS) / LATENCY   |              HCLK (in MHz) (CPU frequency)                    |
 *  |                               |---------------|---------------|---------------|---------------|
 *  |                               | Voltage Range | Voltage Range | Voltage Range | Voltage Range |
 *  |                               | 2.7 V - 3.6 V | 2.4 V - 2.7 V | 2.1 V - 2.4 V | 1.71 V - 2.1 V|
 *  |-------------------------------|---------------|---------------|---------------|---------------|
 *  | 0 WS (1 CPU cycle)            | 0 < HCLK ≤ 30 | 0 < HCLK ≤ 24 | 0 < HCLK ≤ 18 | 0 < HCLK ≤ 16 |
 *  |-------------------------------|---------------|---------------|---------------|---------------|
 *  | 1 WS (2 CPU cycles)           |30 < HCLK ≤ 60 |24 < HCLK ≤ 48 |18 < HCLK ≤ 36 |16 < HCLK ≤ 32 |
 *  |-------------------------------|---------------|---------------|---------------|---------------|
 *  | 2 WS (3 CPU cycles)           |60 < HCLK ≤ 84 |48 < HCLK ≤ 72 |36 < HCLK ≤ 54 |32 < HCLK ≤ 48 |
 *  |-------------------------------|---------------|---------------|---------------|---------------|
 *  | 3 WS (4 CPU cycles)           |      -        |72 < HCLK ≤ 84 |54 < HCLK ≤ 72 |48 < HCLK ≤ 64 |
 *  |-------------------------------|---------------|---------------|---------------|---------------|
 *  | 4 WS (5 CPU cycles)           |      -        |       -       |72 < HCLK ≤ 84 |64 < HCLK ≤ 80 |
 *  |-------------------------------|---------------|---------------|---------------|---------------|
 *  | 5 WS (6 CPU cycles)           |      -        |       -       |       -       |80 < HCLK ≤ 84 |
 *  |_______________________________|_______________|_______________|_______________|_______________|
 *
 *  So when the operating voltage is increased, the flash performance also increases, so at higher voltages, flash can work fast thus the processor doesn't needs to wait and can complete the read/write/erase
 *  operations with the minimum delay in flash access. Along with this, increasing the operating voltage increases flash performance in a limited sense, so while working with higher frequencies than 84 MHz may  
 *  need some non-zero wait states if same flash is used.
 *  Above table is for a general idea about the relation between WS and voltage range for specific operating clock speed range of the microprocessor.
 *  STM32F4xx after reset operates at 16 MHz which is in the range of operable frequency with zero WS even at the lowest voltage range.
 */







#endif /* __FLASH_PROG_H */
