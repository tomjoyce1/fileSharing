// NavButton.qml
import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Controls.Material 2.15
import QtQuick.Layouts 1.15

Button {
    id: control
    property alias iconCode: iconLabel.text
    property alias labelText: textLabel.text
    property bool hovered: false

    flat: true
    Layout.fillWidth: true
    height: 40

    // highlight on hover
    background: Rectangle {
        anchors.fill: parent
        color: control.hovered
            ? Material.color(Material.DeepPurple, Material.Shade300)
            : "transparent"
        radius: 4
    }

    RowLayout {
        anchors.fill: parent
        anchors.margins: 8
        spacing: 8



        // the actual text
        Label {
            id: textLabel
            text: qsTr("All files")
            font.pixelSize: 16
            color: control.hovered
                ? Material.accent
                : Material.onSurface
        }
    }

    MouseArea {
        anchors.fill: parent
        hoverEnabled: true
        onEntered: control.hovered = true
        onExited : control.hovered = false
        onClicked: console.log("nav to", textLabel.text)
    }
}
