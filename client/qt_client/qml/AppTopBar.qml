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

        // — Settings button —
        ToolButton {
            icon.name: "settings"
            Layout.preferredWidth: 40
            Layout.preferredHeight: 40
            background: Rectangle {
                anchors.fill: parent
                radius: width/2
                color: "white"
            }
        }

        // — Avatar button (stub) —
        // swap "avatar.png" for your real path
        Rectangle {
            width: 40; height: 40; radius: 20
            color: "white"
            Image {
                anchors.fill: parent
                anchors.margins: 2
                fillMode: Image.PreserveAspectCrop
                source: "qrc:/icons/avatar.png"
            }
        }
    }
}
