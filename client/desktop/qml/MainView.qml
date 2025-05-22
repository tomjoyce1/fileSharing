// qml/MainView.qml
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

ApplicationWindow {
    width: 960
    height: 540
    visible: true
    title: qsTr("Gobbler — main")

    RowLayout {
        anchors.fill: parent
        spacing: 0

        Sidebar {                       // ← new component
            Layout.fillHeight: true
        }

        FileTable {                // ← here’s our list
            Layout.fillWidth: true
            Layout.fillHeight: true
        }
    }
}
