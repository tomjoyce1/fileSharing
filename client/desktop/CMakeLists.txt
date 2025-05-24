cmake_minimum_required(VERSION 3.16)
project(epic_desktop LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# only these C++ components:
find_package(Qt6 REQUIRED COMPONENTS
        Gui
        Qml
        Quick
        QuickControls2
        QuickDialogs
)

add_executable(epic_desktop
        src/main.cpp
        src/FileDialogHelper.h
)

target_link_libraries(epic_desktop PRIVATE
        Qt6::Gui
        Qt6::Qml
        Qt6::Quick
        Qt6::QuickControls2
        Qt6::QuickDialogs
)

qt_policy(SET QTP0001 NEW)

qt6_add_qml_module(epic_desktop
        URI     EpicClient
        VERSION 1.0
        QML_FILES
        qml/MainView.qml
        qml/Sidebar.qml
        qml/FileTable.qml
        qml/FileRow.qml
        qml/FileUploadArea.qml
)


qt6_add_resources(epic_desktop FILES icons.qrc fonts.qrc)

qt6_import_plugins(epic_desktop
)

qt_finalize_executable(epic_desktop)
