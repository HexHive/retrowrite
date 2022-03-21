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
    std::printf("I'm in Rectangle::hello() :)\n");
  }
  Rectangle() {
    std::printf("I'm in the Rectangle constructor, yay !\n");
  }
};

Rectangle global_rectangle;

class Circle: public Shape {
public:
  virtual void draw() {
    throw std::logic_error("This cannot be done !\n");
  }
  void hello() {
    std::printf("I'm in Circle::hello() :)\n");
  }
  Circle() {
    std::printf("I'm in the Circle constructor, yay !\n");
  }
};

Circle global_circle;

int main(int argc, char *argv[]) {
  Shape *shape;

  if (argc == 2) {
    shape = new Shape();
    global_rectangle.hello();
    global_circle.hello();
  } else {
    shape = new Rectangle();
  }

  try {
    shape->draw();
  } catch (...) {
    std::printf("Error caught !\n");
  }

  delete shape;
}
