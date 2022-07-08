CC := gcc
CFLAGS := $(CFLAGS) -pthread -g -Wall -masm=intel
SHELLCODE_CFLAGS := -Wl,-N -nostdlib -static -masm=intel

# useful for shellcode.
ASM_SRCS := $(wildcard *.s)
ELFS := $(patsubst %.s,%.elf,$(ASM_SRCS))
RAW := $(patsubst %.elf,%.raw,$(ELFS))

C_SRCS := $(wildcard *.c)
BINS := $(patsubst %.c,%.bin,$(C_SRCS))

.PHONY: all clean

all: $(RAW) $(BINS)

%.elf: %.s
	@$(CC) $(SHELLCODE_FLAGS) $< -o $@

%.raw: %.elf
	objcopy --dump-section .text=$@ $<

%.bin: %.c
	@$(CC) $(CFLAGS) -o $@ $<


clean: $(ELFS) $(RAW) $(BINS)
	@rm -f $^
