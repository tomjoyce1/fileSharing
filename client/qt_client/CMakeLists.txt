cmake_minimum_required(VERSION 3.16)
project(qt_client LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC   ON)
set(CMAKE_AUTORCC   ON)
set(CMAKE_AUTOUIC   ON)

find_package(Qt6 REQUIRED COMPONENTS
    Gui
    Qml
    Quick
    QuickControls2
    QuickDialogs2
    Widgets

)

add_executable(qt_client
    src/main.cpp
    src/LoginHandler.cpp
    src/LoginHandler.h
        src/LoginHandler.cpp
        src/LoginHandler.cpp
)

target_link_libraries(qt_client PRIVATE
    Qt6::Gui
    Qt6::Qml
    Qt6::Quick
    Qt6::QuickControls2
    Qt6::QuickDialogs2
    Qt6::Widgets
)

# Bundle ALL QML under the prefix "/" in the QRC:
qt6_add_resources(qt_client
    PREFIX /
    FILES
        qml/MainView.qml
        qml/Sidebar.qml
        qml/FileRow.qml
        qml/FileTable.qml
        qml/Login.qml
        qml/FileUploadArea.qml
        qml/NavButton.qml
        qml/AppTopBar.qml
        resources/fonts/MaterialIcons-Regular.ttf

        assets/BLACKs.png
        assets/graybg.jpg
        assets/image1.png
        assets/SHAREBLACK.png
        "assets/product-sans/Product Sans Regular.ttf"
        "assets/product-sans/Product Sans Bold.ttf"
        "assets/product-sans/Product Sans Italic.ttf"

)

qt6_import_plugins(qt_client)
qt_finalize_executable(qt_client)
