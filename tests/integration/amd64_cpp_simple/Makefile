
TARGETS=simple simple.s simple_compare

CXX=clang++

LDFLAGS=-v -fPIC -fPIE -pie -g -Wl,-z,relro,-z,now -fno-rtti
CXXFLAGS=-v -std=c++20 -Wall -Werror -fPIC -fPIE -g -fno-rtti

CXX_SFLAGS=-std=c++20 -Wall -Werror -fPIC -fPIE

.PHONY: clean

all: $(TARGETS)

clean:
	rm -rf *.o $(TARGETS)

simple: simple.o
	$(CXX) $(LDFLAGS) $< -o $@

simple_compare: simple.o cppabi.o 
	$(CXX) $(LDFLAGS) $^ -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -g -o $@ -c $^

simple.s: simple.cpp
	$(CXX) $(CXX_SFLAGS) -masm=intel -S -o $@ -c $^

rerun: clean reb

retrowrite: all
	retrowrite simple simple_rw.s

reb: retrowrite
	$(CXX) -o rebuilt simple_rw.s
	./rebuilt
