// FileTable.qml
import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Controls.Material 2.15
import QtQuick.Layouts 1.15

Item {
    id: root
    property ListModel model


    Layout.fillWidth: true
    Layout.fillHeight: true

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        // — Header Row —
        RowLayout {
            Layout.fillWidth: true
            Layout.margins: 8
            spacing: 12

            Label { text: qsTr("Name");     font.bold: true; Layout.preferredWidth: 280; horizontalAlignment: Text.AlignLeft;  verticalAlignment: Text.AlignVCenter }
            Label { text: qsTr("Size");     font.bold: true; Layout.preferredWidth: 100; horizontalAlignment: Text.AlignRight; verticalAlignment: Text.AlignVCenter }
            Label { text: qsTr("Modified"); font.bold: true; Layout.preferredWidth: 140; horizontalAlignment: Text.AlignLeft;  verticalAlignment: Text.AlignVCenter }
            Label { text: qsTr("Shared");   font.bold: true; Layout.preferredWidth: 100; horizontalAlignment: Text.AlignRight; verticalAlignment: Text.AlignVCenter }

            Item { Layout.fillWidth: true }
            Item { Layout.preferredWidth: 96 }  // for the 3 action icons
        }

        // — Rows —
        ListView {
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true

            model: root.model
            spacing: 2

            delegate: FileRow {

                fileName:   name
                fileSize:   size
                modified:   modified
                sharedTo:   sharedTo

                onDownloadRequested: console.log("Download", name)
                onShareRequested:    console.log("Share", name)
                onMenuRequested:     console.log("Menu", name)
            }
        }
    }
}
