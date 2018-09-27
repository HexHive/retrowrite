CC?=clang
CDIR=$(shell pwd)
BUILD=$(CDIR)/build/

all: $(BUILD)overflow_heap $(BUILD)overflow_heap_asan $(BUILD)overflow_stack $(BUILD)overflow_stack_asan $(BUILD)overflow_global $(BUILD)overflow_global_asan $(BUILD)stack_example

$(BUILD)stack_example: stack_example.c
	$(CC) stack_example.c -o $@ -fsanitize=address --save-temps

$(BUILD)tinylib.o: tinylib.c
	$(CC) -c $< -o $@ -fpic

$(BUILD)libtiny.so: $(BUILD)tinylib.o
	$(CC) -shared -o $@ $< 

$(BUILD)tinylib_asan.o: tinylib.c
	$(CC) -c $< -fpic -o $@ -fsanitize=address --save-temps -fverbose-asm

$(BUILD)libtinyasan.so: $(BUILD)tinylib_asan.o
	$(CC) -shared -o $@ $<

$(BUILD)overflow_heap_asan: $(BUILD)libtinyasan.so
	$(CC) -L$(BUILD) -Wall -o $@ tiny.c -DHEAP_OVERFLOW=1 -ltinyasan -fsanitize=address

$(BUILD)overflow_heap: $(BUILD)libtiny.so
	$(CC) -L$(BUILD) -Wall -o $@ tiny.c -DHEAP_OVERFLOW=1 -ltiny -fsanitize=address

$(BUILD)overflow_stack_asan: $(BUILD)libtinyasan.so
	$(CC) -L$(BUILD) -Wall -o $@ tiny.c -DSTACK_OVERFLOW=1 -ltinyasan -fsanitize=address

$(BUILD)overflow_stack: $(BUILD)libtiny.so
	$(CC) -L$(BUILD) -Wall -o $@ tiny.c -DSTACK_OVERFLOW=1 -ltiny -fsanitize=address

$(BUILD)overflow_global_asan: $(BUILD)libtinyasan.so
	$(CC) -L$(BUILD) -Wall -o $@ tiny.c -DGLOBAL_OVERFLOW=1 -ltinyasan -fsanitize=address

$(BUILD)overflow_global: $(BUILD)libtiny.so
	$(CC) -L$(BUILD) -Wall -o $@ tiny.c -DGLOBAL_OVERFLOW=1 -ltiny -fsanitize=address

clean:
	rm $(BUILD)*
