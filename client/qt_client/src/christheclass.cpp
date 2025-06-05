#include "ChrisTheClass.h"

int increment(int x) {
    std::cout << "[increment] incrementing " << x << " → " << (x + 1) << std::endl;
    return x + 1;
}

int square(int x) {
    std::cout << "[square] squaring " << x << " → " << (x * x) << std::endl;
    return x * x;
}

void applyFunction(int (*func)(int), int value) {
    std::cout << "[applyFunction] Applying function to " << value << ": "
              << func(value) << std::endl;
}

int (*chooseFunction(const std::string& name))(int) {
    if (name == "inc") {
        return increment;
    } else {
        return square;
    }
}

ChrisTheClass::ChrisTheClass(const std::string& name)
    : name(name)
{
    std::cout << "[ChrisTheClass] Creating Chris named \"" << this->name
              << "\". Prepare for hilarity!" << std::endl;
}

ChrisTheClass::~ChrisTheClass() {
    std::cout << "[ChrisTheClass] Destroying Chris named \"" << name
              << "\". Farewell!" << std::endl;
}

void ChrisTheClass::greet() const {
    std::cout << "[ChrisTheClass] " << name << " says: \"Hello, world!\"" << std::endl;
}

void ChrisTheClass::greet(const std::string& toWhom) const {
    std::cout << "[ChrisTheClass] " << name
              << " greets " << toWhom
              << " with a thumbs up!" << std::endl;
}

ChrisTheClass ChrisTheClass::operator+(const ChrisTheClass& other) const {
    std::string combined = name + "-" + other.name;
    std::cout << "[ChrisTheClass] Combining \"" << name << "\" + \""
              << other.name << "\" → \"" << combined << "\". Epic!" << std::endl;
    return ChrisTheClass(combined);
}

int (*ChrisTheClass::getFunction(const std::string& funcName) const)(int) {
    return chooseFunction(funcName);
}

void ChrisTheClass::info() const {
    std::cout << "[ChrisTheClass] Info: \"" << name
              << "\" is the funniest Chris in all of UL!" << std::endl;
}

std::ostream& operator<<(std::ostream& os, const ChrisTheClass& obj) {
    os << "ChrisTheClass(\"" << obj.name << "\")";
    return os;
}
