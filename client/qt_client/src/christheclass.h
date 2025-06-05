#pragma once

#include <iostream>
#include <string>


template<typename T>
T multiply(T a, T b) {
    return a * b;
}


template<typename T>
class ChrisBox {
private:
    T content;
public:
    ChrisBox(const T& cont) : content(cont) {
        std::cout << "[ChrisBox] Created a box for Chris with content: "
                  << content << std::endl;
    }
    void show() const {
        std::cout << "[ChrisBox] Displaying content: " << content << std::endl;
    }
};


int increment(int x);
int square(int x);


void applyFunction(int (*func)(int), int value);

int (*chooseFunction(const std::string& name))(int);


class ChrisTheClass {
private:
    std::string name;

public:
    // Constructor & Destructor
    ChrisTheClass(const std::string& name);
    ~ChrisTheClass();

    // FUNCTION OVERLOADING: greet()
    void greet() const;
    void greet(const std::string& toWhom) const;

    ChrisTheClass operator+(const ChrisTheClass& other) const;

    int (*getFunction(const std::string& funcName) const)(int);

    void info() const;

    friend std::ostream& operator<<(std::ostream& os, const ChrisTheClass& obj);
};


std::ostream& operator<<(std::ostream& os, const ChrisTheClass& obj);

