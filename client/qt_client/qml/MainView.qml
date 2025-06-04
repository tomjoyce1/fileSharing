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
    // a very light purple backgroun

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
                ListElement { name: "Design Materials.zip";              size: "4.9 MB";  }
                ListElement { name: "Branding Package.pdf";              size: "3.7 MB";   }
                ListElement { name: "Key Visuals.jpg";                   size: "64 KB";    }
                ListElement { name: "POSM mockup.jpg";                   size: "127 KB";  }
                ListElement { name: "Social Media Template 01.pptx";     size: "6.2 MB";   }
                ListElement { name: "Social Media Template 02.pptx";     size: "7.1 MB";   }
                ListElement { name: "Quotation / Invoice Tem... .xlsx";   size: "116 KB";   }
                ListElement { name: "Clients Document Te... .docx";     size: "93 MB";    }
                ListElement { name: "Contract Template.docx";            size: "87 MB";    }
                ListElement { name: "Clients Report Form New.docx";     size: "78 MB";   }
                ListElement { name: "Content";                           size: "—";     }
                ListElement { name: "Content";                           size: "—";      }
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
