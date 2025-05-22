import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

ListView {
    id: list
    clip: true
    model: ListModel {
        ListElement { n: "Design Materials.pdf"; s: "4.9 MB";  m: "Jun 23 2023"; sh: "5 users"; ico: "qrc:/icons/pdf.svg" }
        ListElement { n: "Branding Package.pdf"; s: "3.7 MB";  m: "Jun 23 2023"; sh: "5 users"; ico: "qrc:/icons/pdf.svg" }
        ListElement { n: "Key Visuals.jpg";      s: "64 KB";   m: "Jun 23 2023"; sh: "5 users"; ico: "qrc:/icons/image.svg" }
    }

    delegate: FileRow {
        fileName  : n
        fileSize  : s
        modified  : m
        sharedTo  : sh
        iconSource: ico

        onDownloadRequested: console.log("download", n)
        onShareRequested   : console.log("share", n)
        onMenuRequested    : console.log("menu",  n)
    }

}
