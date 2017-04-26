#include "scutils.h"

SCManager::SCManager() {
  LONG rval;
  rval = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &_context);

  if (rval != SCARD_S_SUCCESS) {
    printf("Fail during establishing context\n");
    exit(0); // TODO: throw exception
  }

  LPTSTR pmszReaders = NULL;
  LPTSTR pReader;
  DWORD cch = SCARD_AUTOALLOCATE;

  // Retrieve the list the readers.
  // hSC was set by a previous call to SCardEstablishContext.
  rval = SCardListReaders(_context, NULL, (LPTSTR)&pmszReaders, &cch );

  if (rval != SCARD_S_SUCCESS) {
    printf("Fail during listing reading\n");
    exit(0); // TODO: throw exception
  }

  // Do something with the multi string of readers.
  // Output the values.
  // A double-null terminates the list of values.
  pReader = pmszReaders;
  while ( '\0' != *pReader ) {
    // Display the value.
    std::string reader_name(pReader);
    _readers.push_back(reader_name);

    // Advance to the next value.
    pReader = pReader + reader_name.size() + 1;
  }

  // Free the memory.
  rval = SCardFreeMemory( _context, pmszReaders);
  if ( SCARD_S_SUCCESS != rval )
    printf("Failed to free memory\n");
}

void SCManager::connectToCardAndSetQtSESAMApplet() {
  LONG rval;

  // Loop over all readers and find card connected
  for (auto reader : _readers) {
    int tries = NUMBER_OF_TRIES;
    while (tries && (rval = SCardConnect(_context, (LPCTSTR)_readers.at(0).c_str(), SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &_card, &_protocol)) != SCARD_S_SUCCESS) {
        tries--;
    }

    tries = NUMBER_OF_TRIES;
    if (rval == SCARD_S_SUCCESS)
      // CARD FOUND
      break;
  }

  if (rval != SCARD_S_SUCCESS) {
    printf("Connection to card was unsuccessful.\n");
    exit(0); // TODO throw exception
  }


  SCARD_IO_REQUEST pioRecvPci; // Depends on protocol returned in SCardConnect

  BYTE responseBuffer[1024]; // buffer for response
  DWORD responseSize = sizeof(responseBuffer); // Max size of response + afret transmission size of response

  switch(_protocol) {
    case SCARD_PROTOCOL_T0:
      pioRecvPci = *SCARD_PCI_T0;
      break;

    case SCARD_PROTOCOL_T1:
      pioRecvPci = *SCARD_PCI_T1;
      break;
  }

  rval = SCardTransmit(_card, &pioRecvPci, AID, sizeof(AID), NULL, responseBuffer, &responseSize);

  // TODO: check response

  }
