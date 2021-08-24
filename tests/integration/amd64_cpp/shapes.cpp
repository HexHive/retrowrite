
#include <cstdlib>
#include <cstring>
#include <cmath>

#include <iostream>
#include <exception>
#include <numbers> // C++20
#include <stdexcept>

class ExceptionCode {
protected:
    int32_t exception_code;

public:

    ExceptionCode(int32_t code) : exception_code(code) {
    }

    const int32_t error_code() { return exception_code; };
};


class ShapeProgramError : public std::runtime_error, public ExceptionCode {
private:
    char what_[1025];
public:
    ShapeProgramError(const int32_t code, const char* msg) 
        : std::runtime_error(msg), ExceptionCode(code) {
    }

    virtual const char* what() const noexcept {

        std::snprintf((char*)this->what_, sizeof what_,
                "ERROR CODE %d: %s",
                this->exception_code,
                std::runtime_error::what()
                );
        return what_;
    }
};

// This is to mimmick a little bit python
class Object {
protected:
    char const* obj_name;

    // no direct construction, be awkward
    Object() {};
public:

    void set_name(const char* name) {
        size_t len = std::strlen(name);
        if ( len > 255 ) {
            throw ShapeProgramError(101, "Object name is too large"); 
        }
        obj_name = (char*)std::calloc(len+1, sizeof(char));
        std::strcpy(const_cast<char*>(obj_name), name);
    };

    virtual ~Object() {
        if ( obj_name) {
            std::free((char*)obj_name);
            obj_name = nullptr;
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

class Triangle : public Shape, public RegularNGon {
private:
    int b; int h;
public:
    Triangle(int base, int height) : RegularNGon(3), b(base), h(height) {
    }
    virtual ~Triangle() {
    }
    virtual double area() {
        return (0.5)*b*h;
    }
    virtual double circumference() {
        // NOTE: Not actually testing :P
        // TODO: TESTING TESTING REMOVE IN REAL CODE!
        throw ShapeProgramError(100, "TEST TEST TEST!");
        return b+h+(std::sqrt(std::pow(b,2) + std::pow(h,2)));
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
        return (0.5)*(std::numbers::pi)*std::pow(r,2);
    }
    virtual double circumference() {
        return 2*r*(std::numbers::pi);
    }
    
};

class Pentagon : public Shape, public RegularNGon {
private:
    int a;
public:
    Pentagon(int side) : RegularNGon(1), a(side) {
    }
    virtual ~Pentagon() {
    }
    virtual double area() {
        // area = (1/4) * Sqrt(5(5+2Sqrt(5)))a^2
        // Bad programmer tries to fix bug!
        if ( n-1 == 0 ) {
            throw std::invalid_argument("n should be 5 for a pentagon");
        }
        // NOTE: deliberate divide by zero here to trigger an exception.
        return (1/(n-1)) * std::sqrt(n*(n+2*std::sqrt(5)))*std::pow(a,2); 
    }
    virtual double circumference() {
        return n*a;
    };
};

class Hexagon : public Shape, public RegularNGon {
private:
    int a;
public:
    Hexagon(int side) : RegularNGon(6), a(side) {
        // NOTE: deliberate bug, string too long.

    }
    virtual ~Hexagon() {
    }
    virtual double area() {
        // area = 3*Sqrt(3)/2 * a^2 
        double area = ((std::sqrt(3.0)*3.0) / 2.0) * (std::pow(a,2));
        return area;
    }
    virtual double circumference() {
        return n*a;
    };
};

Shape* createshape(const char shapetype) {

    Shape* s;
    switch(shapetype) {
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
    case 'H':
        s = new Hexagon(200);
        s->set_name("HexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagon");
        break;
    case 'G':
        s = new Pentagon(2);
        s->set_name("Pentagon");
        break;
    default:
        throw ShapeProgramError(102, "Unknown Shape Type"); 
    };
    return s;
}

Circle unitCircle(1);
Square unitSquare(1);

void printshapedata(Shape* s) {

    try {
        const char* const name = s->name();
        const double area = s->area();
        const double circ = s->circumference();
        std::printf("Area of %s is %f, Circumference of shape is %f\n", name, area, circ);

    }
    catch (ShapeProgramError& ex) {
        std::printf("%s", ex.what()); 
    }
    catch (std::logic_error& ex) {
        std::printf("THIS IS A BUG IN OUR CODING. PLEASE REPORT THIS ON CI IF YOU SPOT IT.\n");
        std::printf("%s", ex.what()); 
    }
    catch (std::exception& ex) {
        std::printf("%s", ex.what()); 
    }
}

struct early_init {
    early_init() {
        unitSquare.set_name("Unit Square");
        unitCircle.set_name("Unit Circle");
    } 
};

early_init trigger;

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

    try {
        s = createshape(argv[1][0]);
        printshapedata(s);

        std::printf("Data on the unit circle:\n");
        printshapedata(&unitCircle);
        std::printf("Data on the unit square:\n");
        printshapedata(&unitSquare);
    }
    catch (std::runtime_error& e) {
        
        // is it really a shape program error?
        ShapeProgramError* es = dynamic_cast<ShapeProgramError*>(&e);
        if (es) {
            std::printf("%s\n", es->what());
        }
        else {
            std::printf("%s\n", e.what());
        }
    }

    if (s) {
        delete s; s = nullptr;
    }

    return 0;
}
