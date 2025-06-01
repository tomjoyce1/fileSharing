// qml/RegisterView.qml
import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Controls.Material
import QtQuick.Layouts 1.15

Item {
    width: 800; height: 400
    Material.theme: Material.Light
    Material.accent: Material.DeepPurple

    Dialog {
        id: errorDialog
        modal: true
        standardButtons: Dialog.Ok
        title: qsTr("Register failed")

        /* local state that we will fill at run-time */
        property string errorText: ""

        /* the visual content of the dialog */
        contentItem: Text {
            text: errorDialog.errorText      /*  ← note the prefix */
            wrapMode: Text.Wrap
            width: parent.width
        }
    }

    ColumnLayout {
        anchors.centerIn: parent
        spacing: 16
        width: parent.width * 0.3

        Label {
            text: qsTr("Create a Shhhare account")
            font.pixelSize: 28; horizontalAlignment: Text.AlignHCenter
        }

        TextField {
            id: regUser; placeholderText: qsTr("Username")
            Layout.fillWidth: true; Layout.preferredHeight: 44
        }

        TextField {
            id: regPass; placeholderText: qsTr("Password")
            echoMode: TextInput.Password
            Layout.fillWidth: true; Layout.preferredHeight: 44
        }

        TextField {
            id: regConfirm; placeholderText: qsTr("Confirm Password")
            echoMode: TextInput.Password
            Layout.fillWidth: true; Layout.preferredHeight: 44
        }

        Button {
            text: qsTr("Register")
            Layout.fillWidth: true; Layout.preferredHeight: 44
            onClicked: registerHandler.registerUser(regUser.text,
                                                    regPass.text,
                                                    regConfirm.text)
        }

        Connections {
            target: registerHandler

            /* modern handler syntax */
            function onRegisterResult(title, message) {
                if (title === "Success") {
                    appWin.loggedIn = true
                } else {
                    errorDialog.errorText = message   //  ← prefixed
                    errorDialog.open()
                }
            }
        }

        // link back to login
        Label {
            textFormat: Text.RichText
            text: qsTr("Already have an account? <a href='login'>Login</a>")
            horizontalAlignment: Text.AlignHCenter
            MouseArea {
                anchors.fill: parent
                cursorShape: Qt.PointingHandCursor
                onClicked: appWin.authView = "login"
            }
        }
    }
}
