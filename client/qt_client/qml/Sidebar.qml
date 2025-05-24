import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Controls.Material 2.15
import QtQuick.Layouts 1.15


Rectangle {
    id: root
    width: 220
    color: Material.surface
    border.color: Material.divider
    border.width: 1

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 16
        spacing: 24

        Label {
            text: "Gobbler"
            font.pixelSize: 22
            font.bold: true
            color: Material.accent
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

        FileUploadArea {
            onFilesDropped:   console.log("dropped:", fileUrls)
            onUploadRequested: console.log("upload:", fileUrls)
        }

        Item { Layout.fillHeight: true }

        Label {
            text: "Storage used: 75%"
            color: Material.onSurface      // ← use onSurface, not onSurfaceVariant
        }

        ProgressBar {
            value: 0.75
            Layout.fillWidth: true
        }
    }
}
