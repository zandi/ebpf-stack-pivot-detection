CC := gcc
CFLAGS := $(CFLAGS) -pthread -g -Wall -masm=intel
SHELLCODE_CFLAGS := -Wl,-N -nostdlib -static -masm=intel

MONO_CC := mcs

# useful for shellcode.
ASM_SRCS := $(wildcard *.s)
ELFS := $(patsubst %.s,%.elf,$(ASM_SRCS))
RAW := $(patsubst %.elf,%.raw,$(ELFS))

C_SRCS := $(wildcard *.c)
C_BINS := $(patsubst %.c,%.bin,$(C_SRCS))

KOTLIN_SRCS := $(wildcard *.kt)
KOTLIN_JARS := $(patsubst %.kt,%.jar,$(KOTLIN_SRCS))
KOTLIN_BINS := $(patsubst %.jar,%.native,$(KOTLIN_JARS))

CSHARP_SRCS := $(wildcard *.cs)
CSHARP_BINS := $(patsubst %.cs,%.exe,$(CSHARP_SRCS))

.PHONY: all clean

all: $(RAW) $(C_BINS) $(CSHARP_BINS)

%.elf: %.s
	@$(CC) $(SHELLCODE_CFLAGS) $< -o $@

%.raw: %.elf
	objcopy --dump-section .text=$@ $<

%.bin: %.c
	@$(CC) $(CFLAGS) -o $@ $<

%.exe: %.cs
	@$(MONO_CC) $<

%.jar: %.kt
	kotlinc $< -include-runtime -d $@

# will need to adjust this if we do any Java tests (added this for kotlin/graalvm)
# you must be using graalvm (source `use_graalvm.sh`)
%.native: %.jar
	native-image -jar $< $@

clean: $(ELFS) $(RAW) $(C_BINS) $(CSHARP_BINS)
	@rm -f $^
