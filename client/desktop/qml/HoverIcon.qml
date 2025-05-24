// HoverIcon.qml
import QtQuick 2.15

Item {
    id: root
    /** The grayscale PNG source */
    property url source
    /** Size of the icon */
    property real iconSize: 20
    /** Colors */
    property color normalColor: "#888888"
    property color hoverColor:  "#FFFFFF"

    width: iconSize; height: iconSize

    // load the PNG but keep it hidden
    Image {
        id: img
        source: root.source
        width: root.iconSize; height: root.iconSize
        visible: false
    }

    // shader that multiplies pixel luminance by the chosen tint
    ShaderEffect {
        anchors.fill: parent
        property variant src: img
        property color tint: mouseArea.containsMouse ? root.hoverColor : root.normalColor
        fragmentShader: "
            varying highp vec2 qt_TexCoord0;
            uniform lowp sampler2D src;
            uniform lowp vec4 tint;
            void main() {
                lowp vec4 c = texture2D(src, qt_TexCoord0.st);
                // assume your PNG is black-on-transparent: multiply by tint.rgb, keep alpha
                gl_FragColor = vec4(c.rgb * tint.rgb, c.a * tint.a);
            }
        "
    }

    MouseArea {
        id: mouseArea
        anchors.fill: parent
        hoverEnabled: true
    }
}
