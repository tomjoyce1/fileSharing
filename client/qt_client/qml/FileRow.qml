// FileRow.qml
import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Controls.Material 2.15
import QtQuick.Layouts 1.15

Item {
    id: root
    width: ListView.view ? ListView.view.width : 640
    height: 48

    // ---------------------------
    // File‐type icon + color logic
    // ---------------------------
    property string fileIcon: {
        var ext = fileName.split(".").pop().toLowerCase()
        switch(ext) {
            case "zip":   return "\ueb2c"
            case "pdf":   return "\ue415"
            case "jpg": case "jpeg": case "png": return "\ue3f4"
            case "ppt": case "pptx": return "\uef3e"
            case "xls": case "xlsx": return "\ue8ef"
            case "doc": case "docx": return "\ue873"
            default:      return "\ue873"
        }
    }
    property color fileColor: {
        var ext = fileName.split(".").pop().toLowerCase()
        switch(ext) {
            case "zip":  return "#8D6E63"
            case "pdf":  return "#E53935"
            case "jpg": case "jpeg": case "png": return "#43A047"
            case "ppt": case "pptx": return "#FB8C00"
            case "xls": case "xlsx": return "#43A047"
            case "doc": case "docx": return "#1E88E5"
            default:     return "#757575"
        }
    }

    // ------------------------------------------------
    // These data properties come from FileTable.delegate
    // ------------------------------------------------
    property alias fileName: nameLabel.text
    property alias fileSize: sizeLabel.text

    // ------------------------------------------------
        // These signals must exist so FileTable.qml can bind to them:
        //   onDownloadRequested, onShareRequested, onDeleteRequested, onRevokeRequested
        // ------------------------------------------------
        signal downloadRequested()
        signal shareRequested()
        signal deleteRequested()
        signal revokeRequested()

        // ------------------------------------------------
        // Hover‐highlight background
        // ------------------------------------------------
        Rectangle {
            anchors.fill: parent
            radius: 4
            color: hoverArea.containsMouse
                   ? Material.color(Material.DeepPurple, Material.Shade100)
                   : "transparent"
            z: -1
        }

        // ----------------------------------------------
        // Main RowLayout: icon, name, size, spacer, buttons
        // ----------------------------------------------
        RowLayout {
            anchors.fill: parent
            anchors.margins: 8
            spacing: 12

            // 1) File‐type Icon
            Label {
                text: fileIcon
                font.pixelSize: 20
                color: fileColor
                Layout.alignment: Qt.AlignVCenter
            }

            // 2) File Name (responsive, max‐width, ellipsize)
            Label {
                id: nameLabel
                text: ""  // bound by FileTable.delegate
                elide: Text.ElideRight
                font.pixelSize: 14
                verticalAlignment: Text.AlignVCenter
                Layout.preferredWidth: 200
                Layout.maximumWidth: 300
                Layout.fillWidth: true
            }

            // 3) File Size (right‐aligned, fixed max‐width)
            Label {
                id: sizeLabel
                text: ""  // bound by FileTable.delegate
                elide: Text.ElideRight
                font.pixelSize: 14
                verticalAlignment: Text.AlignVCenter
                horizontalAlignment: Text.AlignRight
                Layout.preferredWidth: 80
                Layout.maximumWidth: 100
            }

            // 4) Spacer → pushes buttons to the right edge
            Item {
                Layout.fillWidth: true
            }

            // --------------------------------------
            // 5) Pill‐shaped Buttons (Download, Share, Delete, Revoke)
            // --------------------------------------

            // Download Button
            Button {
                id: downloadButton
                text: qsTr("Download")
                Layout.preferredHeight: 28
                padding: 8
                onClicked: downloadRequested()

                background: Rectangle {
                    anchors.fill: parent
                    radius: height / 2
                    color: Material.color(Material.DeepPurple, Material.Shade600)
                }
                contentItem: Label {
                    // Use parent.text instead of control.text
                    text: parent.text
                    color: "white"
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                    font.pixelSize: 12
                }
            }

            // Share Button
            Button {
                id: shareButton
                text: qsTr("Share")
                Layout.preferredHeight: 28
                padding: 8
                onClicked: shareDialog.open()

                background: Rectangle {
                    anchors.fill: parent
                    radius: height / 2
                    color: Material.color(Material.DeepPurple, Material.Shade300)
                }
                contentItem: Label {
                    text: parent.text
                    color: "white"
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                    font.pixelSize: 12
                }
            }

            // Delete Button
            Button {
                id: deleteButton
                text: qsTr("Delete")
                Layout.preferredHeight: 28
                padding: 8
                onClicked: deleteRequested()

                background: Rectangle {
                    anchors.fill: parent
                    radius: height / 2
                    color: "#E53935"  // red‐ish
                }
                contentItem: Label {
                    text: parent.text
                    color: "white"
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                    font.pixelSize: 12
                }
            }

            // Revoke Button
            Button {
                id: revokeButton
                text: qsTr("Revoke")
                Layout.preferredHeight: 28
                padding: 8
                onClicked: revokeDialog.open()

                background: Rectangle {
                    anchors.fill: parent
                    radius: height / 2
                    color: "#FDD835"  // yellow‐ish
                }
                contentItem: Label {
                    text: parent.text
                    color: "white"
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                    font.pixelSize: 12
                }
            }
        }

    MouseArea {
            id: hoverArea
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor

            // Key change: do NOT accept any button clicks here.
            // This allows child Buttons to receive clicks normally.
            acceptedButtons: Qt.NoButton
        }



    // SHARE Dialog
    Dialog {
        id: shareDialog
        modal: true
        standardButtons: Dialog.NoButton
        // Fixed width; height will expand based on content
        width: 320

        background: Rectangle {
            anchors.fill: parent
            color: "white"
            radius: 12
        }

        contentItem: ColumnLayout {
            anchors.fill: parent
            anchors.margins: 16
            spacing: 16

            // Title
            Label {
                text: qsTr("Share a file")
                font.pixelSize: 18
                horizontalAlignment: Text.AlignHCenter
                Layout.alignment: Qt.AlignHCenter
            }

            // Username input field
            TextField {
                id: shareField
                placeholderText: qsTr("Username")
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

            // Buttons: Share (primary) and Cancel (secondary)
            RowLayout {
                spacing: 12
                Layout.alignment: Qt.AlignHCenter

                // Share button (primary)
                Button {
                    text: qsTr("Share")
                    Layout.preferredHeight: 40
                    // Subtract spacing to split field width equally
                    Layout.preferredWidth: (shareField.width - 12) / 2
                    onClicked: {
                        shareRequested(shareField.text)
                        shareField.text = ""
                        shareDialog.close()
                    }
                    background: Rectangle {
                        anchors.fill: parent
                        radius: height / 2
                        color: Material.color(Material.DeepPurple, Material.Shade500)
                    }
                    contentItem: Label {
                        text: parent.text
                        color: "white"
                        font.pixelSize: 14
                        anchors.centerIn: parent
                    }
                }

                // Cancel button (secondary)
                Button {
                    text: qsTr("Cancel")
                    Layout.preferredHeight: 40
                    Layout.preferredWidth: (shareField.width - 12) / 2
                    onClicked: shareDialog.close()
                    background: Rectangle {
                        anchors.fill: parent
                        radius: height / 2
                        color: "#E0E0E0"
                    }
                    contentItem: Label {
                        text: parent.text
                        color: "#424242"
                        font.pixelSize: 14
                        anchors.centerIn: parent
                    }
                }
            }
        }
    }


    // REVOKE Dialog
    Dialog {
        id: revokeDialog
        modal: true
        standardButtons: Dialog.NoButton
        width: 320

        background: Rectangle {
            anchors.fill: parent
            color: "white"
            radius: 12
        }

        contentItem: ColumnLayout {
            anchors.fill: parent
            anchors.margins: 16
            spacing: 16

            // Title
            Label {
                text: qsTr("Revoke a file")
                font.pixelSize: 18
                horizontalAlignment: Text.AlignHCenter
                Layout.alignment: Qt.AlignHCenter
            }

            // Username input field
            TextField {
                id: revokeField
                placeholderText: qsTr("Username")
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

            // Buttons: Revoke (primary) and Cancel (secondary)
            RowLayout {
                spacing: 12
                Layout.alignment: Qt.AlignHCenter

                // Revoke button (primary)
                Button {
                    text: qsTr("Revoke")
                    Layout.preferredHeight: 40
                    Layout.preferredWidth: (revokeField.width - 12) / 2
                    onClicked: {
                        revokeRequested(revokeField.text)
                        revokeField.text = ""
                        revokeDialog.close()
                    }
                    background: Rectangle {
                        anchors.fill: parent
                        radius: height / 2
                        color: "#FDD835"
                    }
                    contentItem: Label {
                        text: parent.text
                        color: "white"
                        font.pixelSize: 14
                        anchors.centerIn: parent
                    }
                }

                // Cancel button (secondary)
                Button {
                    text: qsTr("Cancel")
                    Layout.preferredHeight: 40
                    Layout.preferredWidth: (revokeField.width - 12) / 2
                    onClicked: revokeDialog.close()
                    background: Rectangle {
                        anchors.fill: parent
                        radius: height / 2
                        color: "#E0E0E0"
                    }
                    contentItem: Label {
                        text: parent.text
                        color: "#424242"
                        font.pixelSize: 14
                        anchors.centerIn: parent
                    }
                }
            }
        }
    }


}
