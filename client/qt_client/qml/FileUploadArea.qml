import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Controls.Material
import QtQuick.Layouts 1.15

Item {
    id: root
    Layout.fillWidth: true
    Layout.preferredHeight: 180

    signal filesDropped(var urls)
    signal uploadRequested(var urls)
    signal cancelRequested()

    property var lastFiles: []

    Rectangle {
        id: frame
        anchors.fill: parent
        color: Material.color(Material.DeepPurple, Material.Shade50)
        radius: 8

        DropArea {
            anchors.fill: parent
            onDropped: {
                root.lastFiles = drop.urls
                filesDropped(drop.urls)
            }
        }

        ColumnLayout {
            anchors.fill: parent
            anchors.margins: 12
            spacing: 16
            id: column


            Label {
                text: qsTr("Drop Files Here")
                font.pixelSize: 16
                color: Material.onSurface
                horizontalAlignment: Text.AlignHCenter
                Layout.alignment: Qt.AlignHCenter
                topPadding: 10

            }

            Label {
                text: qsTr("OR")
                font.pixelSize: 12
                color: Material.color(Material.DeepPurple, Material.Shade400)
                horizontalAlignment: Text.AlignHCenter
                Layout.alignment: Qt.AlignHCenter
            }


            Button {
                text: qsTr("Browse files")
               flat: true
               leftPadding: 0; rightPadding: 0; topPadding: 0; bottomPadding: 0
               background: Rectangle { color: "transparent" }
               font.pixelSize: 16
               Layout.alignment: Qt.AlignHCenter
               Component.onCompleted: __behavior.cursorShape = Qt.PointingHandCursor

            }


            RowLayout {
                Layout.alignment: Qt.AlignHCenter
                spacing: 5
                anchors.bottom: column.bottom


                Button {
                    id: uploadBtn
                    text: qsTr("Upload")
                    enabled: root.lastFiles.length > 0
                    width: 50; height: 30
                    background: Rectangle {
                        color: Material.surface
                        border.color: Material.accent
                        border.width: 1
                        radius: 4
                    }
                    contentItem: Label {
                        text: uploadBtn.text
                        anchors.centerIn: parent
                        font.pixelSize: 11
                        color: Material.accent
                    }
                    onClicked: uploadRequested(root.lastFiles)
                    Component.onCompleted: __behavior.cursorShape = Qt.PointingHandCursor
                }


                Button {
                    id: cancelBtn
                    text: qsTr("Cancel")
                    width: 50; height: 30
                    background: Rectangle {
                        color: Material.accent
                        radius: 4
                    }
                    contentItem: Label {
                        text: cancelBtn.text
                        anchors.centerIn: parent
                        font.pixelSize: 11
                        color: Material.surface
                    }
                    onClicked: cancelRequested()
                    Component.onCompleted: __behavior.cursorShape = Qt.PointingHandCursor
                }
            }

        }
    }
}
