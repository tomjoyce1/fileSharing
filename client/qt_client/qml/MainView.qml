import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Controls.Material 2.15
import QtQuick.Layouts 1.15

ApplicationWindow {
    id: appWin
    width: 960
    height: 540
    visible: true
    title: qsTr("Gobbler — main")
    Material.theme: Material.Light
    Material.accent: Material.DeepPurple

    // Top‐level split: sidebar | mainArea
    RowLayout {
        anchors.fill: parent
        spacing: 0

        // — Sidebar —
        Sidebar {
            id: sidebar
            Layout.preferredWidth: 220
            Layout.fillHeight: true
        }

        // — Main area on the right —
        //    contains a toolbar and the FileTable
        ColumnLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: 0

            AppTopBar
            {
                Layout.fillWidth: true
            }

            // 2) File table fills the rest
            FileTable {
                Layout.fillWidth: true
                Layout.fillHeight: true
                // model: demoFiles
            }
        }
    }
}
