CC=gcc
CDIR=$(shell pwd)
BUILD=$(CDIR)/build/

all: $(BUILD)memac $(BUILD)memac_sib

$(BUILD)%: %.c
	$(CC) -c $< -o $@ -pie -fsanitize=address --save-temps -fverbose-asm -O3

clean:
	rm $(BUILD)* *.s *.i *.bc
