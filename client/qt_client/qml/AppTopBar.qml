import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Controls.Material 2.15
import QtQuick.Layouts 1.15

Rectangle {
    id: toolbar
    width: parent ? parent.width : 960
    height: 64
    color: Material.color(Material.DeepPurple, Material.Shade500)
    radius: 0

    RowLayout {
        anchors.fill: parent
        anchors.margins: 12
        spacing: 16

        // — Search pill —
        Item {
            id: searchItem
            Layout.preferredWidth: 360
            Layout.preferredHeight: 40
            Layout.alignment: Qt.AlignVCenter

            Rectangle {
                anchors.fill: parent
                radius: height / 2
                color: Material.color(Material.DeepPurple, Material.Shade400)
            }

            ToolButton {
                anchors.verticalCenter: parent.verticalCenter
                anchors.left: parent.left
                anchors.leftMargin: 8
                icon.name: "search"
                background: null
                icon.color: "white"
            }

            TextField {
                anchors.fill: parent
                leftPadding: 36
                placeholderText: qsTr("Search…")
                color: "white"
                placeholderTextColor: "#DDDDDD"
                background: null
                font.pixelSize: 14
                // no explicit height here
            }
        }

        // spacer
        Item { Layout.fillWidth: true }

        ToolButton {
            id: settingsButton
            icon.name: "settings"
            Layout.preferredWidth: 40
            Layout.preferredHeight: 40

            background: Rectangle {
                anchors.fill: parent
                radius: width / 2
                color: "white"
            }

            /* ⇨ open the dialog */
            onClicked: settingsDialog.open()
        }

        Dialog {
                    id: settingsDialog
                    modal: true
                    standardButtons: Dialog.NoButton
                    width: 320
                    implicitHeight: contentItem.implicitHeight + 32

                    background: Rectangle {
                        anchors.fill: parent
                        color: "white"
                        radius: 12
                    }

                    contentItem: ColumnLayout {
                        anchors.fill: parent
                        anchors.margins: 24
                        spacing: 16

                        /* Title */
                        Label {
                            text: qsTr("User Settings")
                            font.pixelSize: 20
                            horizontalAlignment: Text.AlignHCenter
                            Layout.alignment: Qt.AlignHCenter
                        }

                        /* ─── New Password Field ─── */
                        TextField {
                            id: newPasswordField
                            placeholderText: qsTr("New Password")
                            echoMode: TextInput.Password
                            Layout.fillWidth: true
                            height: 40
                            font.pixelSize: 14

                            background: Rectangle {
                                anchors.fill: parent
                                color: "#F5F5F5"
                                radius: 6
                                border.color: "#CCCCCC"
                                border.width: 1
                            }
                            padding: 8
                        }

                        /* ─── Confirm New Password Field ─── */
                        TextField {
                            id: confirmPasswordField
                            placeholderText: qsTr("Confirm Password")
                            echoMode: TextInput.Password
                            Layout.fillWidth: true
                            height: 40
                            font.pixelSize: 14

                            background: Rectangle {
                                anchors.fill: parent
                                color: "#F5F5F5"
                                radius: 6
                                border.color: "#CCCCCC"
                                border.width: 1
                            }
                            padding: 8
                        }

                        /* ─── Change Password Button ─── */
                        Button {
                            text: qsTr("Change Password")
                            Layout.fillWidth: true
                            Layout.preferredHeight: 40

                            onClicked: {
                                settingsDialog.close()
                                passwordHandler.changePassword(
                                    newPasswordField.text,          // newPwd
                                    confirmPasswordField.text       // confirmPwd
                                )
                            }

                            background: Rectangle {
                                anchors.fill: parent
                                radius: height / 2
                                color: Material.color(Material.Indigo, Material.Shade400)
                            }
                            contentItem: Label {
                                text: parent.text
                                color: "white"
                                font.pixelSize: 14
                                anchors.centerIn: parent
                            }
                        }
                    }
                }

    }
}
