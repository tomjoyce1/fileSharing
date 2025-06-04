
// qml/Login.qml
import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Controls.Material
import QtQuick.Layouts 1.15

Item {
    width: 800; height: 400
    Material.theme: Material.Light
    Material.accent: Material.DeepPurple

    Dialog {
        id: errorDialog; modal: true; standardButtons: Dialog.Ok
        title: qsTr("Login failed")
        contentItem: Text { text: errorText; wrapMode: Text.Wrap; width: parent.width }
    }

    ColumnLayout {
        anchors.centerIn: parent
        spacing: 16
        width: parent.width * 0.3

        Label {
            text: qsTr("Sign in to Shhhare")
            font.pixelSize: 28; horizontalAlignment: Text.AlignHCenter
        }

        TextField {
            id: usernameField
            placeholderText: qsTr("Username")
            Layout.fillWidth: true; Layout.preferredHeight: 44
        }

        TextField {
            id: passwordField
            placeholderText: qsTr("Password")
            echoMode: TextInput.Password
            Layout.fillWidth: true; Layout.preferredHeight: 44
        }

        Button {
            text: qsTr("Login")
            Layout.fillWidth: true; Layout.preferredHeight: 44
            onClicked: loginHandler.validateLogin(usernameField.text, passwordField.text)
        }

        Connections {
            target: loginHandler
            onLoginResult: {
                if (title === "Success") {
                    appWin.loggedIn = true
                } else {
                    errorText = message
                    errorDialog.open()
                }
            }
        }

        // link to register
        Label {
            textFormat: Text.RichText
            text: qsTr("Don't have an account? <a href='register'>Sign up</a>")
            horizontalAlignment: Text.AlignHCenter
            MouseArea {
                anchors.fill: parent
                cursorShape: Qt.PointingHandCursor
                onClicked: appWin.authView = "register"
            }
        }
    }
}
