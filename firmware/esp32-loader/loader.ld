/* The loader runs from SRAM disjoint from the application's segments and
 * the ROM boot stack: code at the top 16 KB of SRAM0 (IRAM 0x4009C000),
 * data in SRAM1 pool 7/6 (DRAM 0x3FFF0000). */
MEMORY
{
    DRAM (rw) : ORIGIN = 0x3FFF0000, LENGTH = 32K
    IRAM (x)  : ORIGIN = 0x4009C000, LENGTH = 16K
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

ets_printf = 0x40007d54;
esp_rom_spiflash_write = 0x40062d50;
esp_rom_spiflash_read = 0x40062ed8;
esp_rom_spiflash_wait_idle = 0x400622c0;
g_rom_flashchip = 0x3ffae270;
