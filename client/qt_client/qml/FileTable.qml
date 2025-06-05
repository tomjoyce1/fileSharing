// FileTable.qml
import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Controls.Material 2.15
import QtQuick.Layouts 1.15
import Qt.labs.platform 1.1

Item {
    id: root
    width:  "parent" in root ? root.parent.width : 640
    height: "parent" in root ? root.parent.height : 480

    // ─────────────────────────────────────────
    // Our dynamic ListModel, cleared + repopulated on filesLoaded(...)
    // ─────────────────────────────────────────
    ListModel {
        id: fileModel
        // Each element will hold:
        //    file_id  (int)
        //    name     (string)
        //    size     (string)
        //    modified (QDateTime as string, or displayable text)
        //    is_owner (bool)
        //    is_shared (bool)
        //    shared_from (string)
    }

    // ─────────────────────────────────────────
    // Listen for the C++ signal “filesLoaded” and update `fileModel`
    // ─────────────────────────────────────────
    Connections {
        target: fileListHandler   // fileListHandler was registered in main.cpp
        onFilesLoaded: {
            fileModel.clear()
            for (var i = 0; i < decryptedFiles.length; ++i) {
                var f = decryptedFiles[i]
                // decryptedFiles[i] is a QVariantMap with keys:
                //   file_id, filename, size, modified (QDateTime), is_owner, is_shared, shared_from
                fileModel.append({
                    "file_id":    f.file_id,
                    "name":       f.filename,
                    "size":       f.size,
                    "modified":   f.modified.toString(Qt.ISODate),
                                 // or format as you like
                    "is_owner":   f.is_owner,
                    "is_shared":  f.is_shared,
                    "shared_from":f.shared_from
                })
            }
        }
        onErrorOccurred: {
            // If you want to show an error popup:
            console.error("Error retrieving file list: " + message)
        }
    }

    Connections {
        target: downloadHandler
        onFileReady: console.log("File", fileName, "written to Downloads")
    }


    Text {
            id: noFilesText
            text: qsTr("No Files")
            font.pixelSize: 18
            color: "#666666"
            anchors.centerIn: parent
            visible: fileModel.count === 0
        }

    // ─────────────────────────────────────────
    // ListView that uses our “fileModel” and FileRow delegate
    // ─────────────────────────────────────────
    ListView {
        id: fileListView
        anchors.fill: parent
        spacing: 2
        model: fileModel
        clip: true

        delegate: FileRow {
            fileId: file_id             // pass model’s file_id into FileRow.fileId
            fileName: name              // model.name
            fileSize: size              // model.size

            // Wire up the row’s signals to C++ (or JS) slots:
            onDownloadRequested: function(theFileId) {
                console.log("QML → downloadRequested(", theFileId, ")");
                console.log("downloadHandler is:", downloadHandler);
                if (downloadHandler) {
                    downloadHandler.downloadFile(theFileId);
                } else {
                    console.warn("downloadHandler is undefined—cannot call downloadFile()");
                }
            }

            onShareRequested: {
                console.log("QML → shareRequested(" + fileId + ", " + arguments[1] + ")")
            }
            onDeleteRequested: {
                console.log("QML → deleteRequested(" + fileId + ")")
                fileListHandler.deleteFile(fileId)
            }
            onRevokeRequested: {
                console.log("QML → revokeRequested(" + fileId + ", " + arguments[1] + ")")
                fileListHandler.revokeFile(fileId, arguments[1])
            }
        }
    }
}
