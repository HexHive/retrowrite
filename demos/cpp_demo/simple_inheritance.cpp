class Shape {
public:
  virtual void draw() {}
};

class Rectangle : public Shape {
public:
  virtual void draw() {}
};

int main(int argc, char *argv[]) {
  Shape *shape;

  if (argc == 0) {
    shape = new Shape();
  } else {
    shape = new Rectangle();
  }

  shape->draw();

  delete shape;
}
