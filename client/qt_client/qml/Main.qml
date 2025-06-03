import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Controls.Material 2.15
import QtQuick.Window 2.15

ApplicationWindow {
    id: appWin
    width: 960
    height: 540
    visible: true
    title: qsTr("Shhhare")

    FontLoader {
        id: materialIconsFont
        source: "qrc:/assets/fonts/MaterialIcons-Regular.ttf"
    }
    FontLoader {
        id: productSansRegular
        source: "qrc:/assets/fonts/ProductSansRegular.ttf"
    }
    FontLoader {
        id: productSansBold
        source: "qrc:/assets/fonts/ProductSansBold.ttf"
    }





    Material.theme: Material.Light
    Material.primary: Material.DeepPurple
    Material.accent: Material.DeepPurple

    property bool loggedIn: false
    property string authView: "login"

    Loader {
        id: pageLoader
        anchors.fill: parent
        source: loggedIn
            ? "qrc:/qml/MainView.qml"
            : authView === "login"
                ? "qrc:/qml/Login.qml"
                : "qrc:/qml/Register.qml"
    }
}
