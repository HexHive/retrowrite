#include <exception>
#include <stdexcept>
#include <cstdlib>
#include <cstring>

class Shape {
public:
  virtual void draw() {}
};

class Rectangle : public Shape {
public:
  virtual void draw() {
    throw std::logic_error("This cannot be done !\n");
  }
  void hello() {
    std::printf("I'm here :)\n");
  }
  Rectangle() {
    std::printf("I'm being constructed, yay !\n");
  }
};

Rectangle azerty;

int main(int argc, char *argv[]) {
  std::printf("We're in main.\n");
  Shape *shape;

  if (argc == 2) {
    shape = new Shape();
    azerty.hello();
  } else {
    shape = new Rectangle();
  }

  try {
    shape->draw();
  } catch (...) {
    std::printf("Error caught !\n");
  }

  delete shape;
  return 0;
}
