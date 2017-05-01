#ifndef PINWINDOW_H
#define PINWINDOW_H

#include <QDialog>
#include <QShowEvent>
#include <QCloseEvent>
#include <QEvent>
#include <QScopedPointer>
#include <QSettings>
#include <QtWidgets>

#include "ui_pinwindow.h"
#include "util.h"
#include "global.h"

namespace Ui {
  class PinWindowDialog;
}


class PinWindow : public QDialog {

  Q_OBJECT
public:
  explicit PinWindow(QWidget *parent = Q_NULLPTR);

  QString getPin() {
    return ui->pin->text();
  }

  ~PinWindow();

signals:
  void accepted(void);
  void rejected(void);

private slots:
void checkSize(QString pin);

private:
  Ui::PinWindowDialog* ui;
};

#endif // PINWINDOW_H
