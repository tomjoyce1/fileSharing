import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Controls.Material
import QtQuick.Layouts 1.15

Item {                      //  ◄── was ApplicationWindow
    anchors.fill: parent
    id: appWin
    width: 960
    height: 540
    property bool loggedIn: false
    visible: true

    Material.theme: Material.Light
    Material.accent: Material.DeepPurple

    Component.onCompleted: {
            console.log("MainView: calling listAllFiles(1) right after login")
            fileListHandler.listAllFiles(1)
        }


    RowLayout {
        anchors.fill: parent
        spacing: 0

        // — Sidebar —
        Sidebar {
            appwin:appWin
            Layout.preferredWidth: 220
            Layout.fillHeight: true
        }

        // — Main Area —
        ColumnLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: 0

            // Top toolbar
            AppTopBar {
                Layout.fillWidth: true
            }


            // The white “card” container, under the top bar
            Item {
                Layout.fillWidth: true
                Layout.fillHeight: true
                Layout.margins: 16

                Rectangle {
                    anchors.fill: parent
                    color: "white"
                    radius: 8

                    // Inset the FileTable inside
                    FileTable {
                        anchors.fill: parent
                        anchors.margins: 12
                    }
                }
            }
        }
    }

}
