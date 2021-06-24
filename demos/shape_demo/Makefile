TARGETS=shapes shapes.s shapes.asan

CXX=clang++

LDFLAGS=-fPIC -fPIE -pie -g -Wl,-z,relro,-z,now
CXXFLAGS=-std=c++20 -Wall -Werror -fPIC -fPIE -g

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

shapes.asan: shapes
	retrowrite --asan ./shapes ./shapes.asan.s
	sed -i 's/asan_init_v4/asan_init/g' shapes.asan.s
	${CXX} shapes.asan.s -lasan -o shapes.asan
