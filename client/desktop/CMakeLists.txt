cmake_minimum_required(VERSION 3.16)
project(epic_desktop LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)   # meta-object compiler
set(CMAKE_AUTOUIC ON)   # if you ever add .ui files
set(CMAKE_AUTORCC ON)   # for resources

find_package(Qt6 REQUIRED COMPONENTS Widgets Network)

add_executable(epic_desktop
        src/main.cpp
        src/MainWindow.cpp
        src/MainWindow.h
)

target_link_libraries(epic_desktop
        PRIVATE Qt6::Widgets Qt6::Network
)
