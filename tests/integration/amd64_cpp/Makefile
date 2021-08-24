
TARGETS=shapes shapes.s

CXX=clang++

LDFLAGS=-v -fPIC -fPIE -pie -g -Wl,-z,relro,-z,now
CXXFLAGS=-v -std=c++20 -Wall -Werror -fPIC -fPIE -g

CXX_SFLAGS=-std=c++20 -Wall -Werror -fPIC -fPIE

.PHONY: clean

all: $(TARGETS)

clean:
	rm -rf *.o $(TARGETS)

shapes: shapes.o
	$(CXX) $(LDFLAGS) $< -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -o $@ -c $^

shapes.s: shapes.cpp
	$(CXX) $(CXX_SFLAGS) -masm=intel -S -o $@ -c $^

rerun: clean all rebuilt

retrowrite:
	retrowrite shapes shapes_rw.s

rebuilt: retrowrite
	$(CXX) -o rebuilt shapes_rw.s
	./rebuilt
