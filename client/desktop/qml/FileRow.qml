import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Controls.Material 2.15
import QtQuick.Layouts 1.15

Item {
    id: root
    width: ListView.view ? ListView.view.width : 640
    height: 48

    // expose these so the delegate can bind into them:
    property alias fileName: nameLabel.text
    property alias fileSize: sizeLabel.text
    property alias modified: modifiedLabel.text
    property alias sharedTo: sharedLabel.text

    signal downloadRequested()
    signal shareRequested()
    signal menuRequested()

    Rectangle {
        anchors.fill: parent
        radius: 4
        color: hoverArea.containsMouse
            ? Material.accent.lighter(1.4)
            : "transparent"
        z: -1
    }

    RowLayout {
        anchors.fill: parent
        anchors.margins: 8
        spacing: 12

        Label {
            id: nameLabel
            Layout.preferredWidth: 300
            Layout.fillHeight: true
            elide: Text.ElideRight
            verticalAlignment: Text.AlignVCenter
        }

        Label {
            id: sizeLabel
            Layout.preferredWidth: 100
            Layout.fillHeight: true
            horizontalAlignment: Text.AlignRight
            verticalAlignment: Text.AlignVCenter
        }

        Label {
            id: modifiedLabel
            Layout.preferredWidth: 140
            Layout.fillHeight: true
            verticalAlignment: Text.AlignVCenter
        }

        Label {
            id: sharedLabel
            Layout.preferredWidth: 100
            Layout.fillHeight: true
            horizontalAlignment: Text.AlignRight
            verticalAlignment: Text.AlignVCenter
        }

        Item { Layout.fillWidth: true }

        ToolButton {
            icon.name: "download"
            Layout.alignment: Qt.AlignVCenter
            onClicked: downloadRequested()
        }
        ToolButton {
            icon.name: "share"
            Layout.alignment: Qt.AlignVCenter
            onClicked: shareRequested()
        }
        ToolButton {
            text: "\u22EE"
            font.pixelSize: 18
            Layout.alignment: Qt.AlignVCenter
            onClicked: menuRequested()
        }
    }

    MouseArea {
        id: hoverArea
        anchors.fill: parent
        hoverEnabled: true
    }
}
