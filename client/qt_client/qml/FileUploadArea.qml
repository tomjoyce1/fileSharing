import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Controls.Material 2.15
import QtQuick.Layouts 1.15
import Qt.labs.platform 1.1

Item {
    id: root
    Layout.fillWidth: true
    Layout.preferredHeight: 180

    // ── Signals ─────────────────────────────────
    signal filesDropped(var urls)
    signal uploadRequested(var urls)
    signal cancelRequested()

    // ── Store the last‐chosen files as an array of QUrl
    property var lastFiles: []

    Rectangle {
        id: frame
        anchors.fill: parent
        color: Material.color(Material.DeepPurple, Material.Shade50)
        radius: 8

        DropArea {
            anchors.fill: parent
            onDropped: {
                // drop.urls is array<QUrl>
                root.lastFiles = drop.urls
                root.filesDropped(drop.urls)
            }
        }

        // ── Hidden FileDialog ──────────────────────
        FileDialog {
            id: filePicker
            folder: StandardPaths.writableLocation(StandardPaths.HomeLocation)
            nameFilters: ["All Files (*.*)"]
            onAccepted: {
                root.lastFiles = filePicker.fileUrls
                root.filesDropped(filePicker.fileUrls)
            }
        }

        ColumnLayout {
            anchors.fill: parent
            anchors.margins: 12
            spacing: 16
            id: column

            Label {
                text: qsTr("Drop Files Here")
                font.pixelSize: 16
                color: Material.onSurface
                horizontalAlignment: Text.AlignHCenter
                Layout.alignment: Qt.AlignHCenter
                topPadding: 10
            }

            Label {
                text: qsTr("OR")
                font.pixelSize: 12
                color: Material.color(Material.DeepPurple, Material.Shade400)
                horizontalAlignment: Text.AlignHCenter
                Layout.alignment: Qt.AlignHCenter
            }

            Button {
                text: qsTr("Browse files")
                flat: true
                leftPadding: 0; rightPadding: 0; topPadding: 0; bottomPadding: 0
                background: Rectangle { color: "transparent" }
                font.pixelSize: 16
                Layout.alignment: Qt.AlignHCenter
                onClicked: filePicker.open()
            }

            RowLayout {
                Layout.alignment: Qt.AlignHCenter
                spacing: 5

                Button {
                    id: uploadBtn
                    text: qsTr("Upload")
                    enabled: root.lastFiles.length > 0
                    width: 80; height: 30
                    background: Rectangle {
                        color: Material.surface
                        border.color: Material.accent
                        border.width: 1
                        radius: 4
                    }
                    contentItem: Label {
                        text: uploadBtn.text
                        anchors.centerIn: parent
                        font.pixelSize: 11
                        color: Material.accent
                    }

                    onClicked: {
                        //
                        // Each element of root.lastFiles is actually a JS string like
                        //   "file:///C:/Users/shado/Downloads/NIST.FIPS.204.pdf"
                        // (DropArea hands you plain strings, not real QUrl‐objects.)  We must
                        // strip off "file:///" (or "file://") ourselves so that C++ sees
                        // a pure filesystem path ("C:/Users/…/NIST.FIPS.204.pdf").
                        //
                        var pathList = []
                        for (var i = 0; i < root.lastFiles.length; ++i) {
                            var s = root.lastFiles[i]

                            // If s is already a QUrl object, it would have toLocalFile():
                            if (typeof s === "object" && typeof s.toLocalFile === "function") {
                                pathList.push(s.toLocalFile())
                            }
                            else if (typeof s === "string") {
                                // Strip leading "file://" (Unix or Windows).
                                // On Windows you often get "file:///C:/…"
                                var t = s.replace(/^file:\/\//, "")
                                // If we’re on Windows, t might now be "/C:/…". Remove that slash:
                                if (Qt.platform.os === "windows" &&
                                    t.length >= 3 &&
                                    t[0] === "/" &&
                                    t[1].match(/[A-Za-z]/) &&
                                    t[2] === ":"
                                ) {
                                    t = t.substring(1)
                                }
                                pathList.push(t)
                            }
                            else {
                                // Fallback: coerce to string and strip:
                                var t2 = s.toString().replace(/^file:\/\//, "")
                                if (Qt.platform.os === "windows" &&
                                    t2.length >= 3 &&
                                    t2[0] === "/" &&
                                    t2[1].match(/[A-Za-z]/) &&
                                    t2[2] === ":"
                                ) {
                                    t2 = t2.substring(1)
                                }
                                pathList.push(t2)
                            }
                        }
                        uploadHandler.uploadFiles(pathList)
                    }
                }

                Button {
                    id: cancelBtn
                    text: qsTr("Cancel")
                    width: 80; height: 30
                    background: Rectangle {
                        color: Material.accent
                        radius: 4
                    }
                    contentItem: Label {
                        text: cancelBtn.text
                        anchors.centerIn: parent
                        font.pixelSize: 11
                        color: Material.onSurface
                    }
                    onClicked: root.cancelRequested()
                }
            }
        }
    }

    // ── Listen to UploadHandler.uploadResult(title, message) ───────
    Connections {
        target: uploadHandler
        function onUploadResult(title, message) {
            console.log("UploadHandler says:", title, message)
            // (You could pop up a MessageDialog here if you like.)
        }
    }
}
