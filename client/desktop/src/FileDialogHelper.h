// FileDialogHelper.h
#pragma once
#include <QObject>
#include <QStringList>
#include <QFileDialog>

class FileDialogHelper : public QObject {
    Q_OBJECT
public:
    explicit FileDialogHelper(QObject* parent = nullptr): QObject(parent) {}

    Q_INVOKABLE QStringList openFileNames() {
        return QFileDialog::getOpenFileNames(
            nullptr,
            tr("Select Files to Upload"),
            QDir::homePath(),
            tr("All Files (*)")
        );
    }
};
