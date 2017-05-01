#include "pinwindow.h"

PinWindow::PinWindow(QWidget *parent) :
  QDialog(parent),
  ui(new Ui::PinWindowDialog())
{
  ui->setupUi(this);
  setWindowIcon(QIcon(":/images/ctSESAM.ico"));
  ui->label->setStyleSheet("font-weight: bold");
  setWindowTitle(QString("%1 %2").arg(AppName).arg(isPortable() ? " - PORTABLE" : ""));

  QObject::connect(ui->buttons, SIGNAL(rejected()), SIGNAL(rejected()));
  QObject::connect(ui->buttons, SIGNAL(accepted()), SIGNAL(accepted()));
  QObject::connect(ui->pin, SIGNAL(textEdited(QString)), SLOT(checkSize(QString)));

  ui->buttons->button(QDialogButtonBox::Ok)->setEnabled(false);
  ui->pin->setEchoMode(QLineEdit::Password);
}

void PinWindow::checkSize(QString pin) {
  ui->buttons->button(QDialogButtonBox::Ok)->setEnabled(pin.size() == 4);
}

PinWindow::~PinWindow() {
  delete ui;
}
