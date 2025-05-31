import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Controls.Material
import QtQuick.Layouts 1.15

ApplicationWindow {
    id: appWin
    width: 960
    height: 540
    property bool loggedIn: false
    visible: true
    title: qsTr("Gobbler — main")

    Material.theme: Material.Light
    Material.accent: Material.DeepPurple
    // a very light purple background
    color: Material.color(Material.DeepPurple, Material.Shade50)

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

            // A demo ListModel so you can see scrolling
            ListModel {
                id: demoFiles
                ListElement { name: "Design Materials.zip";              size: "4.9 MB";  modified: "Jun 23, 2023"; sharedTo: "5 users" }
                ListElement { name: "Branding Package.pdf";              size: "3.7 MB";  modified: "Jun 22, 2023"; sharedTo: "5 users" }
                ListElement { name: "Key Visuals.jpg";                   size: "64 KB";   modified: "Jun 21, 2023"; sharedTo: "5 users" }
                ListElement { name: "POSM mockup.jpg";                   size: "127 KB";  modified: "Jun 20, 2023"; sharedTo: "5 users" }
                ListElement { name: "Social Media Template 01.pptx";     size: "6.2 MB";  modified: "Jun 19, 2023"; sharedTo: "5 users" }
                ListElement { name: "Social Media Template 02.pptx";     size: "7.1 MB";  modified: "Jun 18, 2023"; sharedTo: "5 users" }
                ListElement { name: "Quotation / Invoice Tem... .xlsx";   size: "116 KB";  modified: "Jun 17, 2023"; sharedTo: "5 users" }
                ListElement { name: "Clients Document Te... .docx";     size: "93 MB";   modified: "Jun 16, 2023"; sharedTo: "5 users" }
                ListElement { name: "Contract Template.docx";            size: "87 MB";   modified: "Jun 15, 2023"; sharedTo: "5 users" }
                ListElement { name: "Clients Report Form New.docx";     size: "78 MB";   modified: "Jun 14, 2023"; sharedTo: "5 users" }
                ListElement { name: "Content";                           size: "—";       modified: "18/05/2022"; sharedTo: "5 users" }
                ListElement { name: "Content";                           size: "—";       modified: "27/01/2023"; sharedTo: "5 users" }
                // add more ListElement entries if you like…
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
                        model: demoFiles
                    }
                }
            }
        }
    }

}
