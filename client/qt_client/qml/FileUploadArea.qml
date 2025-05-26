// FileUploadArea.qml
import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Controls.Material 2.15
import QtQuick.Layouts 1.15

Item {
    id: root
    Layout.fillWidth: true
    Layout.preferredHeight: 200

    signal filesDropped(var urls)
    signal uploadRequested(var urls)
    signal cancelRequested()

    property var lastFiles: []

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 8
        spacing: 12

        // — Dashed drop region —
        Item {
            id: dropFrame
            Layout.fillWidth: true
            Layout.preferredHeight: 120

            // Canvas draws the dashed border
            Canvas {
                anchors.fill: parent
                onPaint: {
                    var ctx = getContext("2d");
                    ctx.clearRect(0,0,width,height);
                    ctx.setLineWidth(1);
                    ctx.strokeStyle = Material.divider;
                    ctx.setLineDash([4,4]);
                    ctx.strokeRect(0.5,0.5,width-1,height-1);
                }
            }

            // Accept drag-and-drop
            DropArea {
                anchors.fill: parent
                onDropped: {
                    root.lastFiles = drop.urls;
                    filesDropped(drop.urls);
                }
            }

            // Centered instructions & Browse link
            ColumnLayout {
                anchors.centerIn: parent
                spacing: 4


                Label {
                    text: qsTr("Drop files here")
                    font.pixelSize: 14
                    color: Material.onSurface
                }
                Label {
                    text: qsTr("or")
                    font.pixelSize: 12
                    color: Material.onSurfaceVariant
                }
                Button {
                    text: qsTr("Browse files")
                    flat: true
                    background: Rectangle { color: "transparent" }
                    font.pixelSize: 14

                    onClicked: cancelRequested()    // hook this up to open your file dialog
                }
            }
        }

        // — Action buttons —
        RowLayout {
            Layout.fillWidth: true
            spacing: 8

            Button {
                text: qsTr("Cancel")
                flat: true
                onClicked: cancelRequested()
            }
            Button {
                text: qsTr("Upload")
                enabled: lastFiles.length > 0
                onClicked: uploadRequested(lastFiles)
            }
        }
    }
}
