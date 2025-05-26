// Sidebar.qml
import QtQuick          2.15
import QtQuick.Controls 2.15
import QtQuick.Controls.Material 2.15
import QtQuick.Layouts  1.15

Rectangle {
    id: root
    width: 220
    color: Material.color(Material.DeepPurple, Material.Shade200)
    border.color: Material.divider
    border.width: 1

    // 1) Load your Material Icons font from the resource bundle
    FontLoader {
        id: materialIcons
        source: "qrc:/resources/fonts/MaterialIcons-Regular.ttf"
        onStatusChanged: console.log("Icon-font status:", status, name)
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 16
        spacing: 0

        // — Logo / Title —
        Label {
            text: "Gobbler"
            font.pixelSize: 22
            font.bold: true
            color: Material.DeepPurple700
            horizontalAlignment: Text.AlignHCenter
            Layout.alignment: Qt.AlignHCenter
        }

        // — Navigation items —
        ListModel {
            id: navModel
            ListElement { iconCode: "\uE2C8"; labelText: qsTr("All files") }
            ListElement { iconCode: "\uE7FD"; labelText: qsTr("My files") }
            ListElement { iconCode: "\uE7EF"; labelText: qsTr("Shared with me") }
        }

        ColumnLayout {
            spacing: 4

            Repeater {
                model: navModel
                delegate: ToolButton {
                    // enable hovered, remove manual MouseArea
                    hoverEnabled: true
                    flat: true
                    Layout.fillWidth: true
                    height: 40
                    leftPadding: 8; rightPadding: 8; topPadding: 4; bottomPadding: 4

                    background: Rectangle {
                        anchors.fill: parent
                        radius: 4
                        color: hovered
                              ? Material.color(Material.DeepPurple, Material.Shade300)
                              : "transparent"
                    }

                    contentItem: RowLayout {
                        anchors.fill: parent
                        anchors.margins: 4
                        spacing: 8

                        // icon glyph
                        Label {
                            font.family: materialIcons.name
                            font.pixelSize: 20
                            text: iconCode
                            color: hovered
                                  ? Material.accent
                                  : Material.onSurface
                        }

                        // text label
                        Label {
                            text: labelText
                            font.pixelSize: 16
                            color: hovered
                                  ? Material.accent
                                  : Material.onSurface
                        }
                    }

                    onClicked: console.log("Navigate to", labelText)
                }
            }
        }

        // — divider —
        Rectangle {
            height: 1
            color: Material.divider.lighter(1.5)
            Layout.fillWidth: true
            Layout.margins: 12
        }

        // — FileUploadArea —
        Frame {
            background: Rectangle {
                color: Material.surface
                border.color: Material.divider
                radius: 8
            }
            Layout.fillWidth: true
            Layout.preferredHeight: 140

            FileUploadArea {
                anchors.fill: parent
                anchors.margins: 8
            }
        }

        // — divider —
        Rectangle {
            height: 1
            color: Material.divider.lighter(1.5)
            Layout.fillWidth: true
            Layout.margins: 12
        }

        // — Storage usage —
        Label {
            text: qsTr("Storage used: %1%").arg(75)
            font.pixelSize: 14
            color: Material.onSurfaceVariant
            Layout.margins: 8
        }
        ProgressBar {
            value: 0.75
            Layout.fillWidth: true
        }
    }
}
