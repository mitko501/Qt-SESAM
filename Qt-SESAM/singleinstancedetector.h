/*

    Copyright (c) 2015 Oliver Lau <ola@ct.de>, Heise Medien GmbH & Co. KG

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/


#ifndef __SINGLEINSTANCEDETECTOR_H_
#define __SINGLEINSTANCEDETECTOR_H_

#include <QDebug>
#include <QString>
#include <QByteArray>
#include <QSharedMemory>
#include "global.h"
#include "util.h"

class SingleInstanceDetector
{
public:
  static SingleInstanceDetector *instance(void)
  {
    static SingleInstanceDetector *singleInstance = new SingleInstanceDetector;
    return singleInstance;
  }


  bool alreadyRunning(void)
  {
    if (sharedMem->create(1, QSharedMemory::ReadOnly))
      return false;
    qWarning() << sharedMem->errorString();
    return true;
  }


  void release(void)
  {
    if (sharedMem != nullptr)
      sharedMem->detach();
    SafeDelete(sharedMem);
  }


private:
  SingleInstanceDetector(void)
    : sharedMem(new QSharedMemory(AppName))
  { /* ... */ }
  ~SingleInstanceDetector()
  {
    release();
  }
  QSharedMemory *sharedMem;

  static SingleInstanceDetector *singleInstance;
};

#endif // __SINGLEINSTANCEDETECTOR_H_
