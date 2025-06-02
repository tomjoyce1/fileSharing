// qml/Main.qml
import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Controls.Material
import QtQuick.Layouts 1.15

ApplicationWindow {
    id: appWin
    width: 960; height: 540
    visible: true
    title: qsTr("Shhhare")
    Material.theme: Material.Light
    Material.accent: Material.DeepPurple

    // Are we past auth?
    property bool loggedIn: false
    // Which auth screen? "login" or "register"
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
