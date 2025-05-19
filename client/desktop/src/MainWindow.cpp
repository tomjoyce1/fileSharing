#include "MainWindow.h"
#include <QVBoxLayout>
#include <QWidget>
#include <QPushButton>
#include <QLabel>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    auto *central = new QWidget(this);
    auto *layout  = new QVBoxLayout(central);

    auto *title = new QLabel("EPIC File-Sharing Client", central);
    title->setAlignment(Qt::AlignHCenter);

    auto *quitBtn = new QPushButton("Quit", central);
    connect(quitBtn, &QPushButton::clicked, this, &QWidget::close);

    layout->addWidget(title);
    layout->addStretch();
    layout->addWidget(quitBtn);

    setCentralWidget(central);
    resize(600, 400);
}
