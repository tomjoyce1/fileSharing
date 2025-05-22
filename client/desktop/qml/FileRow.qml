// qml/FileRow.qml  – self-contained, reusable row component
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Item {
    width: ListView.view ? ListView.view.width : 640
    height: 38

    /* public properties */
    property alias fileName     : nameLabel.text
    property string fileSize    : "—"
    property string modified    : "—"
    property string sharedTo    : "—"
    property url    iconSource  : ""

    signal downloadRequested()
    signal shareRequested()
    signal menuRequested()

    /* background highlight rectangle */
    Rectangle {
        id: bg
        anchors.fill: parent
        radius: 3
        color: bg.hovered ? "#2f3948" : "transparent"
        z: -1            /* behind the row content */
        property bool hovered: false
    }

    /* actual row content */
    RowLayout {
        anchors.fill: parent
        anchors.margins: 12
        spacing: 16

        Image {                         // use the normal Image element
            source: iconSource
            width: 20; height: 20
            fillMode: Image.PreserveAspectFit
        }

        Label { id: nameLabel; Layout.preferredWidth: 250; elide: Text.ElideRight }

        Label { text: fileSize ; Layout.preferredWidth: 80 ; horizontalAlignment: Text.AlignRight }
        Label { text: modified ; Layout.preferredWidth: 120 }
        Label { text: sharedTo ; Layout.preferredWidth: 80 ; horizontalAlignment: Text.AlignRight }

        Item { Layout.fillWidth: true }      // spacer

        ToolButton { icon.name: "download"; onClicked: downloadRequested() }
        ToolButton { icon.name: "share"   ; onClicked: shareRequested()    }
        ToolButton { text: "\u22ee"; font.pixelSize: 18; onClicked: menuRequested() }
    }

    /* hover handler */
    MouseArea {
        anchors.fill: parent
        hoverEnabled: true
        onEntered: bg.hovered = true
        onExited : bg.hovered = false
    }
}
