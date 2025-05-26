import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Controls.Material
import QtQuick.Layouts 1.15

Rectangle {
    id: uploadArea
    property var appwin

    width: parent.width
    height: 140
    radius: 8
    border.width: 1
    border.color: appwin ? appwin.Material.divider : "gray"
    color: dropArea.containsDrag
        ? (appwin ? appwin.Material.accent.lighter(1.7) : "#2196f3")
        : (appwin ? appwin.Material.background : "white")

    signal filesDropped(var fileUrls)
    signal uploadRequested(var fileUrls)
    signal browseRequested()

    // 1) DropArea for drag-drop
    DropArea {
        id: dropArea
        anchors.fill: parent
        onDropped: filesDropped(drop.urls)
    }

    // 2) UI
    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 12
        spacing: 8

        Label {
            text: qsTr("Drop files here or")
            font.pixelSize: 14
            Layout.alignment: Qt.AlignHCenter
        }

        Button {
            text: qsTr("Browse files…")
            icon.name: "folder-open"
            Layout.preferredWidth: parent.width * 0.6
            onClicked: browseRequested()
        }

        Button {
            text: qsTr("Upload")
            enabled: lastSelected.length > 0
            Layout.preferredWidth: parent.width * 0.6
            onClicked: uploadRequested(lastSelected)
        }
    }

    // remember the last drop/browse result
    property var lastSelected: []
    onFilesDropped: lastSelected = fileUrls
}
