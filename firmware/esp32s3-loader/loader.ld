/* The loader runs from SRAM above the application's segments: code at
 * IRAM 0x403D0000 (DRAM alias 0x3FCE0000), data at DRAM 0x3FCD8000, on
 * the ROM's stack (below 0x3FCEB710). */
MEMORY
{
    DRAM (rw) : ORIGIN = 0x3FCD8000, LENGTH = 32K
    IRAM (x)  : ORIGIN = 0x403D0000, LENGTH = 32K
}

ENTRY(loader_entry)

SECTIONS
{
    .iram : ALIGN(4)
    {
        *(.literal.loader_entry .text.loader_entry)
        *(.literal .text .literal.* .text.*)
        . = ALIGN(4);
    } >IRAM

    .dram : ALIGN(4)
    {
        *(.rodata .rodata.*)
        *(.data .data.*)
        *(.sdata .sdata.*)
        . = ALIGN(4);
    } >DRAM

    .bss (NOLOAD) : ALIGN(4)
    {
        *(.bss .bss.* .sbss .sbss.* COMMON)
    } >DRAM

    /DISCARD/ : { *(.eh_frame) }
}

ets_printf = 0x400005d0;
esp_rom_spiflash_write = 0x40000a14;
esp_rom_spiflash_read = 0x40000a20;
esp_rom_spiflash_unlock = 0x40000a2c;
rom_spiflash_legacy_data = 0x3fceffe4;
