CC=/home/number_four/projects/afl-2.52b/afl-clang
CDIR=$(shell pwd)
BUILD=$(CDIR)/build/

all: $(BUILD)overflow_heap $(BUILD)overflow_stack $(BUILD)overflow_global

$(BUILD)overflow_heap: $(BUILD)libtiny.so
	AFL_USE_ASAN=1 $(CC) -L$(BUILD) -Wall -o $@ tiny.c -DHEAP_OVERFLOW=1 -ltiny -fsanitize=address

$(BUILD)overflow_stack: $(BUILD)libtiny.so
	AFL_USE_ASAN=1 $(CC) -L$(BUILD) -Wall -o $@ tiny.c -DSTACK_OVERFLOW=1 -ltiny -fsanitize=address

$(BUILD)overflow_global: $(BUILD)libtiny.so
	AFL_USE_ASAN=1 $(CC) -L$(BUILD) -Wall -o $@ tiny.c -DGLOBAL_OVERFLOW=1 -ltiny -fsanitize=address

clean:
	rm $(BUILD)*
