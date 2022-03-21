#include <cstdlib>
#include <cstring>
#include <cmath>
#include <iostream>

// #include <numbers> // C++20

// This is to mimmick a little bit python
class Object {
protected:
    char* obj_name;



    // no direct construction, be awkward
    Object() {};
public:
    
    void set_name(const char* name) {
        // TODO: add an exception if name > some value! :P
        size_t len = std::strlen(name);

        this->obj_name = (char*)std::calloc(len+1, sizeof(char));
        std::strcpy(this->obj_name, name);
    };

    virtual ~Object() {
        if (obj_name) {
            std::free(this->obj_name);
            this->obj_name = nullptr;
        }
    }

    const char* const name() {
        return obj_name;
    }
};

// A Mixin, which is useful to mix things up.
class RegularNGon { 
protected:
    int n;
public:
    RegularNGon(int N) : n(N) {
    }

    virtual ~RegularNGon() {
    }
};

class Shape : public Object
{
public:
    Shape() {
    }

    virtual ~Shape() {
    }
    virtual double area() = 0;
    virtual double circumference() = 0;
};

class Parallelogram : public Shape {
protected:
    int b; int h;
public:
    Parallelogram(int base, int height) : b(base), h(height) {
    }

    virtual ~Parallelogram() {

    }

    virtual double area() {
        return b*h;
    }

    virtual double circumference() {
        return 2*(b+h);
    }
};

class Rectangle : public Parallelogram {
public:
    // We are also a parallelogram, instantiate the protected instance variables there.
    Rectangle(int base, int height) : Parallelogram(base,height) {
    }

    virtual ~Rectangle() {
    }

    // Rely on the parent class' area method.
};

class Square: public Rectangle, public RegularNGon {
public:
    // We are also a parallelogram, instantiate the protected instance variables there.
    Square(int length) : Rectangle(length, length), RegularNGon(4) {
    }

    virtual ~Square() {
    }

    virtual double circumference() {
        return this->n * b;
    }
};

class Triangle : public Shape {
private:
    int b; int h;
public:
    Triangle(int base, int height) : b(base), h(height) {
    }
    virtual ~Triangle() {
    }
    virtual double area() {
        return (0.5)*b*h;
    }
    virtual double circumference() {
        return b+h+(std::sqrt(b^2 + h^2));
    };
};

class Circle : public Shape {
private:
    int r;
public:
    Circle(int radius) : r(radius) {
    }
    virtual ~Circle() {
    }
    virtual double area() {
        return (1/2)*(r^2)*(3.14159265); // std::numbers::pi);
    }
    virtual double circumference() {
        return 2*r*(3.14159265); // std::numbers::pi);
    }
    
};

int main(int argc, char** argv) {

    Shape* s = nullptr;

    if ( argc != 2 ) {
        std::printf("Not enough arguments. Specify one letter.\n");
        return -1;
    }

    if ( std::strlen(argv[1]) != 1 ) {
        std::printf("Please pick a single letter argument.\n");
        return -1;
    }

    switch(argv[1][0]) {
    case 'C':
        s = new Circle(4);
        s->set_name("Circle");
        break;
    case 'R':
        s = new Rectangle(6,10);
        s->set_name("Rectangle");
        break;
    case 'P':
        s = new Parallelogram(5,9);
        s->set_name("Parallelogram");
        break;
    case 'S':
        s = new Square(10);
        s->set_name("Square");
        break;
    case 'T':
        s = new Triangle(5,9);
        s->set_name("Triangle");
        break;
    default:
        std::printf("Not a valid shape type. Exiting");
        return -1;
    
    };

    const char* const name = s->name();
    double area = s->area();
    double circ = s->circumference();
    std::printf("Area of %s is %f, Circumference of shape is %f\n", name, area, circ);

    if (s != nullptr) {
        delete s; 
        s = nullptr;
    }

    return 0;
}
