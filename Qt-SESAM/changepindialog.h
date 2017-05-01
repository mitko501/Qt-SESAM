#ifndef CHANGEPINDIALOG_H
#define CHANGEPINDIALOG_H

#include <QDialog>
#include <QtWidgets>
#include "global.h"
#include "util.h"
#include "ui_changepindialog.h"

namespace Ui {
  class ChangePinDialog;
}

class ChangePinDialog : public QDialog
{
  Q_OBJECT

public:
  explicit ChangePinDialog(QWidget *parent = 0);

  QString get_newPIN() {
    return ui->newPIN->text();
  }

  QString get_oldPIN() {
    return ui->oldPIN->text();
  }

  ~ChangePinDialog();

private:
  Ui::ChangePinDialog* ui;
  bool newPIN = false;
  bool oldPIN = false;
  bool repeatPIN = false;

signals:
  void accepted(void);
  void rejected(void);

private slots:
  void checkNewPIN(QString pin);
  void checkOldPIN(QString pin);
  void checkRepeatPIN(QString pin);
  void checkAll();
};

#endif // CHANGEPINDIALOG_H
