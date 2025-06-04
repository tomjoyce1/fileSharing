// Sidebar.qml
import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Controls.Material
import QtQuick.Layouts 1.15

Rectangle {
    id: root
    property var appwin

    width: 220
    color: white

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 14
        spacing: 10

        // — Logo —
        Label {
            text: "SSShare"
            font.pixelSize: 28
            font.bold: true
            color: Material.color(Material.DeepPurple, Material.Shade700)
            horizontalAlignment: Text.AlignHCenter
            Layout.alignment: Qt.AlignHCenter
        }

        // — Nav data —
        ListModel {
            id: navModel
            ListElement { iconCode: "\uE2C8"; labelText: qsTr("All files") }
            ListElement { iconCode: "\uE7FD"; labelText: qsTr("My files") }
            ListElement { iconCode: "\uE7EF"; labelText: qsTr("Shared with me") }
        }

        Repeater {
            model: navModel
            delegate: Rectangle {
                id: navItem
                width: parent ? parent.width : root.width
                height: 30
                color: "transparent"
                property bool hovered: false
                Layout.fillWidth: true

                // icon + text, flush-left with 8px gap
                Row {
                    anchors.left: parent.left
                    anchors.leftMargin: 14
                    anchors.verticalCenter: parent.verticalCenter
                    spacing: 8

                    Label {
                        font.family: materialIcons.name
                        font.pixelSize: 20
                        text: iconCode
                        color: navItem.hovered
                            ? Material.accent
                            : "#212121"
                    }

                    Label {
                        text: labelText
                        font.pixelSize: 16
                        color: navItem.hovered
                            ? Material.accent
                            : "#212121"
                    }
                }

                // MUST come *after* your Row so it's on top
                MouseArea {
                    anchors.fill: parent
                    hoverEnabled: true
                    onEntered:  navItem.hovered = true
                    onExited:   navItem.hovered = false
                    cursorShape: Qt.PointingHandCursor

                    onClicked: {
                        if (labelText === "All files") {
                            console.log("Requesting ALL files (page 1)…")
                            fileListHandler.listAllFiles(1)
                        }
                        else if (labelText === "My files") {
                            console.log("Requesting MY files (page 1)…")
                            fileListHandler.listOwnedFiles(1)
                        }
                        else if (labelText === "Shared with me") {
                            console.log("Requesting SHARED files (page 1)…")
                            fileListHandler.listSharedFiles(1)
                        }
                    }
                }
            }
        }

        // FileUploadArea
        FileUploadArea {
            // signals: uploadRequested, cancelRequested…
        }

        // storage usage
        Label {
            text: qsTr("Storage used: 75%")
            font.pixelSize: 14
            color: Material.onSurfaceVariant
            Layout.margins: 8
        }
        ProgressBar {
            value: 0.75
            Layout.fillWidth: true
        }
    }

    // — Listen for filesLoaded and errorOccurred from C++ —
    Connections {
        target: fileListHandler

        onFilesLoaded: {
            console.log("=== filesLoaded signal received ===")
            for (var i = 0; i < decryptedFiles.length; ++i) {
                var f = decryptedFiles[i]
                console.log(
                    " • id=" + f.file_id
                  + ", name=\"" + f.filename + "\""
                  + ", size=" + f.size
                  + ", modified=" + f.modified.toString()
                  + ", owner?=" + f.is_owner
                  + ", shared?=" + f.is_shared
                  + ", shared_from=" + f.shared_from
                )
            }
        }

        onErrorOccurred: {
            console.error("Error occurred in FileListHandler: " + message)
        }
    }
}
