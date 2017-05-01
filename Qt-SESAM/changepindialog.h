#ifndef CHANGEPINDIALOG_H
#define CHANGEPINDIALOG_H

#include <QDialog>
#include <QtWidgets>

namespace Ui {
  class ChangePinDialog;
}

class ChangePinDialog : public QDialog
{
  Q_OBJECT

public:
  explicit ChangePinDialog(QWidget *parent = 0);
  ~ChangePinDialog();

private:
  Ui::ChangePinDialog *ui;
  bool newPIN = false;
  bool oldPIN = false;
  bool repeatPIN = false;

private slots:
  void checkNewPIN(QString pin);
  void checkOldPIN(QString pin);
  void checkRepeatPIN(QString pin);
  void checkAll();
};

#endif // CHANGEPINDIALOG_H
