import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Controls.Material
import QtQuick.Layouts 1.15


Item {
    id: root
    property ListModel model         // parent will do `model: demoFiles`

    Layout.fillWidth: true
    Layout.fillHeight: true

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        // — header row —
        RowLayout {
            Layout.fillWidth: true
            Layout.margins: 8
            spacing: 12

            Label { text: qsTr("Name");     font.bold: true; Layout.preferredWidth: 300; horizontalAlignment: Text.AlignLeft;  verticalAlignment: Text.AlignVCenter }
            Label { text: qsTr("Size");     font.bold: true; Layout.preferredWidth: 100; horizontalAlignment: Text.AlignRight; verticalAlignment: Text.AlignVCenter }
            Label { text: qsTr("Modified"); font.bold: true; Layout.preferredWidth: 140; horizontalAlignment: Text.AlignLeft;  verticalAlignment: Text.AlignVCenter }
            Label { text: qsTr("Shared");   font.bold: true; Layout.preferredWidth: 100; horizontalAlignment: Text.AlignRight; verticalAlignment: Text.AlignVCenter }

            Item { Layout.fillWidth: true }
            Item { Layout.preferredWidth: 96 }  // reserve space for the three action buttons
        }

        // — actual list of FileRow delegates —
        ListView {
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true

            model: root.model

            delegate: FileRow {
                // these names must match your ListModel roles!
                fileName:   name
                fileSize:   size
                modified:   modified
                sharedTo:   sharedTo

                onDownloadRequested: console.log("dl", name)
                onShareRequested:    console.log("sh", name)
                onMenuRequested:     console.log("…",  name)
            }
            spacing: 2
        }
    }
}
