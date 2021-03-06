#include "changepindialog.h"

ChangePinDialog::ChangePinDialog(QWidget *parent) :
  QDialog(parent),
  ui(new Ui::ChangePinDialog)
{
  ui->setupUi(this);
  setWindowIcon(QIcon(":/images/ctSESAM.ico"));
  setWindowTitle(QString("%1 %2").arg(AppName).arg(isPortable() ? " - PORTABLE" : ""));

  QObject::connect(ui->newPIN, SIGNAL(textEdited(QString)), SLOT(checkNewPIN(QString)));
  QObject::connect(ui->oldPIN, SIGNAL(textEdited(QString)), SLOT(checkOldPIN(QString)));
  QObject::connect(ui->newRepeat, SIGNAL(textEdited(QString)), SLOT(checkRepeatPIN(QString)));
  QObject::connect(ui->buttonBox, SIGNAL(rejected()), SIGNAL(rejected()));
  QObject::connect(ui->buttonBox, SIGNAL(accepted()), SIGNAL(accepted()));

  ui->oldPIN->setEchoMode(QLineEdit::Password);
  ui->newPIN->setEchoMode(QLineEdit::Password);
  ui->newRepeat->setEchoMode(QLineEdit::Password);
}

void ChangePinDialog::checkOldPIN(QString pin) {
  oldPIN = pin.size() == 4;
  checkAll();
}

void ChangePinDialog::checkNewPIN(QString pin) {
  newPIN = pin.size() == 4 && ui->newRepeat->text().size() == 4 && pin == ui->newRepeat->text();
  checkAll();
}

void ChangePinDialog::checkRepeatPIN(QString pin) {
  newPIN = pin.size() == 4 && ui->newPIN->text().size() == 4 && pin == ui->newPIN->text();
  checkAll();
}

void ChangePinDialog::checkAll() {
  ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(newPIN && oldPIN);
}

ChangePinDialog::~ChangePinDialog()
{
  delete ui;
}
