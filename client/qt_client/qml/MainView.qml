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
    Material.accent: Material.Blue


    StackLayout{
    //     page 1
        anchors.fill:parent
        currentIndex: loggedIn ? 1 : 0

        Login{


        }


    // –– page 2) A demo ListModel full of “realistic” placeholders ––
    ListModel {
        id: demoFiles
        ListElement { name: "Contract.pdf";      size: "248 KB";  modified: "Apr 01 2025"; sharedTo: "3 users" }
        ListElement { name: "Invoice_2025.xlsx"; size: "512 KB";  modified: "Apr 02 2025"; sharedTo: "1 user"  }
        ListElement { name: "Presentation.pptx"; size: "1.2 MB";  modified: "Mar 28 2025"; sharedTo: "5 users" }
        ListElement { name: "MeetingNotes.docx"; size: "96 KB";   modified: "Mar 27 2025"; sharedTo: "2 users" }
        ListElement { name: "Specs.pdf";         size: "780 KB";  modified: "Mar 20 2025"; sharedTo: "4 users" }
        ListElement { name: "Logo.ai";           size: "2.4 MB";  modified: "Mar 15 2025"; sharedTo: "6 users" }
        ListElement { name: "Photo1.jpg";        size: "3.1 MB";  modified: "Feb 10 2025"; sharedTo: "1 user"  }
        ListElement { name: "Budget2025.xlsx";   size: "650 KB";  modified: "Feb 05 2025"; sharedTo: "2 users" }
    }

    RowLayout {
        anchors.fill: parent    // ← make it truly span the window
        spacing: 0

        Sidebar {
            appwin:appWin

            Layout.preferredWidth: 220
            Layout.fillHeight: true
        }

        FileTable {
            Layout.fillWidth: true
            Layout.fillHeight: true

            // –– 2) wire up the demo model here ––
            model: demoFiles
        }
    }
    }
}
