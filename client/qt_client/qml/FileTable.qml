import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Controls.Material
import QtQuick.Layouts 1.15

Item {
    id: root
    property ListModel model

    Layout.fillWidth: true
    Layout.fillHeight: true

    ColumnLayout {
        anchors.fill: parent
        spacing: 0


        // — Rows —
        // — Rows —
        ListView {
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true

            model: root.model
            spacing: 2

            delegate: FileRow {
                fileName: name
                fileSize: size

                onDownloadRequested: console.log("Download", name)
                onShareRequested:    console.log("Share", name, "→", username)
                onDeleteRequested:   console.log("Delete", name)
                onRevokeRequested:   console.log("Revoke", name, "←", username)
            }
        }

    }
}
