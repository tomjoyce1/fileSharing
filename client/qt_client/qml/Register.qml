import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Controls.Material 2.15
import QtQuick.Layouts 1.15
import QtQuick.Window 2.15

Item {
    width: 800; height: 400
    Material.theme: Material.Light
    Material.accent: Material.DeepPurple

    Component.onCompleted: {
            console.log("registerHandler is", registerHandler)
        }

    /* ───── Modal error dialog ───── */
    Dialog {
        id: errorDialog
        modal: true
        title: qsTr("Register failed")
        standardButtons: Dialog.Ok

        property string errorText: ""

        contentItem: Text {
            text: errorDialog.errorText
            wrapMode: Text.Wrap
            width: parent ? parent.width : 300
        }
    }

    /* ───── Form ───── */
    ColumnLayout {
        anchors.centerIn: parent
        width: parent.width * 0.3
        spacing: 16

        Label {
            text: qsTr("Create a Shhhare account")
            font.pixelSize: 28
            horizontalAlignment: Text.AlignHCenter
            Layout.alignment: Qt.AlignHCenter
        }

        /* username / password / confirm */
        TextField { id: user;     placeholderText: qsTr("Username");  Layout.fillWidth: true }
        TextField { id: pass;     placeholderText: qsTr("Password");  echoMode: TextInput.Password; Layout.fillWidth: true }
        TextField { id: confirm;  placeholderText: qsTr("Confirm");   echoMode: TextInput.Password; Layout.fillWidth: true }

        /* register button */
        Button {
            text: qsTr("Register")
            Layout.fillWidth: true
            onClicked: {
                   console.log("QML → calling registerUser()")          // ← NEW
                   registerHandler.registerUser(user.text, pass.text, confirm.text)
               }
        }

        /* switch back to login link */
        Label {
            textFormat: Text.RichText
            text: qsTr("Already have an account? <a href=\"login\">Login</a>")
            horizontalAlignment: Text.AlignHCenter
            Layout.alignment: Qt.AlignHCenter

            MouseArea {
                anchors.fill: parent
                onClicked: Qt.application.activeWindow.authView = "login"
                hoverEnabled: true
            }
        }
    }

    Connections {
        target: registerHandler

        function onRegisterResult(title, message) {
                        if (title === "Success") {
                            appWin.loggedIn = true
                            console.log("QML → loggedIn flipped to true")
                        } else {
                            errorDialog.errorText = message
                            errorDialog.open()
                        }
        }
    }

}
