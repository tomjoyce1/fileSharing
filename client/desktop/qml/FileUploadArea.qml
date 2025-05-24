// FileUploadArea.qml
import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Controls.Material 2.15
import QtQuick.Layouts 1.15

Rectangle {
    id: uploadArea
    width: parent.width
    height: 140
    radius: 8
    border.width: 1
    border.color: Material.divider
    color: dropArea.containsDrag
        ? Material.accent.lighter(1.7)
        : Material.background

    signal filesDropped(var fileUrls)
    signal uploadRequested(var fileUrls)
    signal browseRequested()

    // Drag-and-drop surface
    DropArea {
        id: dropArea
        anchors.fill: parent
        onDropped: filesDropped(drop.urls)
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 12
        spacing: 8
        horizontalAlignment: Qt.AlignHCenter
        verticalAlignment: Qt.AlignVCenter

        Label {
            text: qsTr("Drop files here or")
            font.pixelSize: 14
            horizontalAlignment: Text.AlignHCenter
        }

        Button {
            text: qsTr("Browse files…")
            icon.name: "folder-open"
            Layout.preferredWidth: parent.width * 0.6
            onClicked: browseRequested()
        }

        Button {
            text: qsTr("Upload")
            enabled: lastSelected && lastSelected.length > 0
            Layout.preferredWidth: parent.width * 0.6
            onClicked: uploadRequested(lastSelected)
        }
    }

    // keep track of the file list chosen by C++
    property var lastSelected: []
    onFilesDropped: lastSelected = fileUrls
}
