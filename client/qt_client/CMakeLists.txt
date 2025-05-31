cmake_minimum_required(VERSION 3.16)
project(qt_client LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC   ON)
set(CMAKE_AUTORCC   ON)
set(CMAKE_AUTOUIC   ON)

# ─────────────────────────────────────────────────────────────
# 1) Qt6 (exactly as before)
# ─────────────────────────────────────────────────────────────
find_package(Qt6 REQUIRED COMPONENTS
    Gui
    Qml
    Quick
    QuickControls2
    QuickDialogs2
    Widgets
)

# ─────────────────────────────────────────────────────────────
# 2) liboqs (exactly as before)
# ─────────────────────────────────────────────────────────────
set(OQS_SOURCE_DIR "C:/Users/shado/liboqs")
add_subdirectory("${OQS_SOURCE_DIR}" liboqs-build EXCLUDE_FROM_ALL)

# ─────────────────────────────────────────────────────────────
# 3) libsodium (exactly as before, via vcpkg)
# ─────────────────────────────────────────────────────────────
find_package(unofficial-sodium CONFIG REQUIRED)

# ─────────────────────────────────────────────────────────────
# 4) OpenSSL: point CMake at the folder where the .lib files actually are
# ─────────────────────────────────────────────────────────────
set(OPENSSL_ROOT_DIR       "C:/Program Files/OpenSSL-Win64"      CACHE PATH "Path to installed OpenSSL")
set(OPENSSL_INCLUDE_DIR    "${OPENSSL_ROOT_DIR}/include"        CACHE PATH "")

# The installer put libcrypto.lib and libssl.lib under lib/VC/x64/MD/
set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_ROOT_DIR}/lib/VC/x64/MD/libcrypto.lib"   CACHE FILEPATH "")
set(OPENSSL_SSL_LIBRARY    "${OPENSSL_ROOT_DIR}/lib/VC/x64/MD/libssl.lib"      CACHE FILEPATH "")

find_package(OpenSSL REQUIRED)
if(NOT OpenSSL_FOUND)
    message(FATAL_ERROR "Could not find OpenSSL under ${OPENSSL_ROOT_DIR}")
endif()

# ─────────────────────────────────────────────────────────────
add_executable(qt_client
    src/main.cpp
    src/LoginHandler.cpp
    src/LoginHandler.h
    src/RegisterHandler.cpp
    src/RegisterHandler.h

    src/utils/crypto/cryptobase.h
    src/utils/crypto/kem.h
    src/utils/crypto/signer.h

    src/utils/crypto/symmetric.h
    src/utils/crypto/symmetric.cpp

    src/utils/crypto/kem_ecdh.h
    src/utils/crypto/kem_ecdh.cpp

    src/utils/crypto/signer_ed.h
    src/utils/crypto/signer_ed.cpp

    src/utils/crypto/signer_dilithium.h
    src/utils/crypto/signer_dilithium.cpp
    src/utils/crypto/kdf.h src/utils/crypto/kdf.cpp
    src/utils/crypto/hash.h src/utils/crypto/hash.cpp
    src/utils/crypto/keybundle.h src/utils/crypto/keybundle.cpp
)

target_link_libraries(qt_client PRIVATE
    Qt6::Gui
    Qt6::Qml
    Qt6::Quick
    Qt6::QuickControls2
    Qt6::QuickDialogs2
    Qt6::Widgets

    oqs
    unofficial-sodium::sodium
    OpenSSL::Crypto        # Links against C:/Program Files/OpenSSL-Win64/lib/VC/x64/MD/libcrypto.lib
)

target_include_directories(qt_client PRIVATE
    "${CMAKE_BINARY_DIR}/liboqs-build/include"
)

qt6_add_resources(qt_client
    PREFIX /
    FILES
        qml/Main.qml
        qml/MainView.qml
        qml/Sidebar.qml
        qml/FileRow.qml
        qml/FileTable.qml
        qml/Login.qml
        qml/FileUploadArea.qml
        qml/NavButton.qml
        qml/AppTopBar.qml
        qml/Register.qml
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
