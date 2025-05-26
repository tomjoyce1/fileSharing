import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Controls.Material 2.15

Item {
    id: root
    width: ListView.view ? ListView.view.width : 640
    height: 48

    // load Material Icons font
    FontLoader {
        id: materialIcons
        source: "qrc:/resources/fonts/MaterialIcons-Regular.ttf"
    }

    // --- restore these two properties! ---
    property string fileIcon: {
        var ext = fileName.split(".").pop().toLowerCase()
        switch(ext) {
        case "zip":   return "\ueb2c"
        case "pdf":   return "\uE415"
        case "jpg": case "jpeg": case "png": return "\uE3F4"
        case "ppt": case "pptx": return "\uE24E"
        case "xls": case "xlsx": return "\uE24F"
        case "doc": case "docx": return "\uE24D"
        default:      return "\uE24D"
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
    // ---------------------------------------

    // row data (set by FileTable.delegate)
    property alias fileName:   nameLabel.text
    property alias fileSize:   sizeLabel.text
    property alias modified:   modifiedLabel.text
    property alias sharedTo:   sharedLabel.text

    signal downloadRequested()
    signal shareRequested()
    signal menuRequested()

    // hover highlight
    Rectangle {
        anchors.fill: parent
        radius: 4
        color: hoverArea.containsMouse
            ? Material.color(Material.DeepPurple, Material.Shade100)
            : "transparent"
        z: -1
    }

    Row {
        anchors.fill: parent
        anchors.margins: 8
        spacing: 12

        // file-type icon
        Label {
            font.family: materialIcons.name
            font.pixelSize: 20
            text: fileIcon
            color: fileColor
            anchors.verticalCenter: parent.verticalCenter
        }

        // name
        Label {
            id: nameLabel
            elide: Text.ElideRight
            width: 256
            anchors.verticalCenter: parent.verticalCenter
        }

        // size
        Label {
            id: sizeLabel
            width: 100
            horizontalAlignment: Text.AlignRight
            anchors.verticalCenter: parent.verticalCenter
        }

        // modified
        Label {
            id: modifiedLabel
            width: 140
            anchors.verticalCenter: parent.verticalCenter
        }

        // shared to
        Label {
            id: sharedLabel
            width: 100
            horizontalAlignment: Text.AlignRight
            anchors.verticalCenter: parent.verticalCenter
        }

        // download action
        ToolButton {
            icon.name: "file_download"
            icon.color: Material.onSurface
            anchors.verticalCenter: parent.verticalCenter
            onClicked: downloadRequested()
        }

        // share action
        ToolButton {
            icon.name: "share"
            icon.color: Material.color(Material.DeepPurple, Material.Shade800)
            anchors.verticalCenter: parent.verticalCenter
            onClicked: shareRequested()
        }

        // overflow menu
        ToolButton {
            icon.name: "more_vert"
            icon.color: Material.color(Material.DeepPurple, Material.Shade800)
            anchors.verticalCenter: parent.verticalCenter
            onClicked: menuRequested()
        }
    }

    MouseArea {
        id: hoverArea
        anchors.fill: parent
        hoverEnabled: true
        cursorShape: Qt.PointingHandCursor
    }
}
