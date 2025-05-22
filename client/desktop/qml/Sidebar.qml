// qml/Sidebar.qml
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Rectangle {
    id: root
    width: 220                         // fixed width
    color: "#1f2937"                   // dark surface (tailwind gray-800)
    border.color: "#374151"
    border.width: 1

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 16
        spacing: 24

        Label {
            text: "Gobbler"
            font.pixelSize: 22
            font.bold: true
            color: "#3b82f6"
        }

        ColumnLayout {
            spacing: 12
            Repeater {
                model: ["All files", "My files", "Shared with me"]
                delegate: Button {
                    text: modelData
                    flat: true
                    Layout.fillWidth: true
                    font.pixelSize: 16
                    leftPadding: 0
                }
            }
        }

        Item { Layout.fillHeight: true }      // pushes storage bar to bottom

        Label { text: "Storage used: 75 %" ; color: "#d1d5db" }
        ProgressBar {
            value: 0.75
            Layout.fillWidth: true
        }
    }
}
