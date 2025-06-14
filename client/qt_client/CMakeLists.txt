cmake_minimum_required(VERSION 3.16)
project(qt_client LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC   ON)
set(CMAKE_AUTORCC   ON)
set(CMAKE_AUTOUIC   ON)
cmake_policy(SET CMP0144 NEW)


find_package(Qt6 REQUIRED COMPONENTS
    Gui
    Qml
    Quick
    QuickControls2
    QuickDialogs2
    Widgets
    Concurrent
    QuickControls2Material
)

set(BOOST_ROOT       "C:/msys64/mingw64"       CACHE PATH "MSYS2 MinGW64 Boost prefix")
set(BOOST_INCLUDEDIR "${BOOST_ROOT}/include"   CACHE PATH "")
set(BOOST_LIBRARYDIR "${BOOST_ROOT}/lib"       CACHE PATH "")

find_package(Boost 1.70.0 REQUIRED COMPONENTS system)
if (NOT Boost_FOUND)
    message(FATAL_ERROR "Could not find Boost under ${BOOST_ROOT}")
endif()


set(OPENSSL_ROOT_DIR    "C:/msys64/mingw64"  CACHE PATH "MSYS2 MinGW64 OpenSSL prefix")
set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT_DIR}/include" CACHE PATH "")
set(OPENSSL_LIBRARIES   "${OPENSSL_ROOT_DIR}/lib/libssl.a;${OPENSSL_ROOT_DIR}/lib/libcrypto.a"
                        CACHE STRING "MSYS2 MinGW64 OpenSSL libs")

find_package(OpenSSL REQUIRED)
if (NOT OpenSSL_FOUND)
    message(FATAL_ERROR "Could not find OpenSSL under ${OPENSSL_ROOT_DIR}")
endif()

find_path(SODIUM_INCLUDE_DIR
    sodium.h
    HINTS "C:/msys64/mingw64/include"
)
find_library(SODIUM_LIBRARY
    sodium
    HINTS "C:/msys64/mingw64/lib"
)

if (NOT SODIUM_INCLUDE_DIR OR NOT SODIUM_LIBRARY)
    message(FATAL_ERROR "Could not find libsodium under C:/msys64/mingw64")
endif()


find_path(OQS_INCLUDE_DIR
    oqs.h
    HINTS "C:/msys64/mingw64/include/oqs"
)
find_library(OQS_LIBRARY
    oqs
    HINTS "C:/msys64/mingw64/lib"
)

if (NOT OQS_INCLUDE_DIR OR NOT OQS_LIBRARY)
    message(FATAL_ERROR "Could not find liboqs under C:/msys64/mingw64")
endif()

find_package(nlohmann_json REQUIRED)

add_executable(qt_client
    src/main.cpp
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


    src/utils/crypto/hash.h
    src/utils/crypto/hash.cpp
    src/utils/crypto/keybundle.h
    src/utils/crypto/keybundle.cpp

    src/utils/networking/httprequest.h
    src/utils/networking/httprequest.cpp
    src/utils/networking/httpresponse.h
    src/utils/networking/httpresponse.cpp
    src/utils/networking/networkclient.h
    src/utils/networking/networkclient.cpp
    src/utils/networking/asiosslclient.h
    src/utils/networking/asiosslclient.cpp

    src/utils/crypto/derutils.h src/utils/crypto/derutils.cpp
    src/utils/networking/asiohttpclient.h src/utils/networking/asiohttpclient.cpp
    src/utils/crypto/FileClientData.h
    src/utils/clientstore.h src/utils/clientstore.cpp

    src/handlers/LoginHandler.cpp
    src/handlers/LoginHandler.h
    src/handlers/RegisterHandler.cpp
    src/handlers/RegisterHandler.h

    src/handlers/fileuploadhandler.h src/handlers/fileuploadhandler.cpp
    src/utils/handlerutils.h
    src/utils/NetworkAuthUtils.h
    src/config.h src/config.cpp
    src/utils/networking/HttpResult.h
    src/handlers/filelisthandler.h src/handlers/filelisthandler.cpp
    src/handlers/filedownloadhandler.h src/handlers/filedownloadhandler.cpp
    src/handlers/passwordchangehandler.h src/handlers/passwordchangehandler.cpp
    src/handlers/filesharehandler.h src/handlers/filesharehandler.cpp
    src/christheclass.h src/christheclass.cpp
)

target_include_directories(qt_client PRIVATE
    "${Boost_INCLUDEDIR}"
    "${OPENSSL_INCLUDE_DIR}"
    "${SODIUM_INCLUDE_DIR}"
    "${OQS_INCLUDE_DIR}"
)

set(CACERT_PEM "${CMAKE_CURRENT_SOURCE_DIR}/src/cacert.pem")

add_custom_command(
    TARGET qt_client POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CACERT_PEM}"
            $<TARGET_FILE_DIR:qt_client>/cacert.pem
    COMMENT "Copying cacert.pem → output folder"
)

qt6_add_resources(qt_client
    PREFIX /
    FILES
        # QML
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

        # FONTS
        assets/fonts/MaterialIcons-Regular.ttf
        assets/fonts/ProductSansRegular.ttf
        assets/fonts/ProductSansBold.ttf

        # IMAGES
        assets/BLACKs.png
        assets/graybg.jpg
        assets/image1.png
        assets/SHAREBLACK.png
)


target_link_libraries(qt_client PRIVATE
    Qt6::Gui
    Qt6::Qml
    Qt6::Quick
    Qt6::QuickControls2
    Qt6::QuickDialogs2
    Qt6::Widgets
    Qt6::Concurrent
    Qt6::QuickControls2Material

    Boost::system               # (Asio is header-only)
    OpenSSL::Crypto
    OpenSSL::SSL

    "${SODIUM_LIBRARY}"         # libsodium
    "${OQS_LIBRARY}"            # liboqs
    nlohmann_json::nlohmann_json
)
