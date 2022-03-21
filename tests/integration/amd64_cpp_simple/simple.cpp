
#include <iostream>

void exceptional_function() {
	throw std::runtime_error("Hello!");
}

void catch_function() {
	std::printf("We caught it\n");
}

int main() {

	try {
	exceptional_function();
	} catch (std::runtime_error& e) {
		catch_function();
	}
}
