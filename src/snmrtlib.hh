//======================================================================================
// Name        : snmrtlib.hh
// Author      : Dmitry Komyagin
// Version     : 0.8
// Created on  : Oct 16, 2024
// Copyright   : Public domain
// Description : Header file for SNMONITOR RuntimeControl library, Linux, ISO C++14
//======================================================================================

/*************************************************************************************************
 * THIRD-PARTY SOFTWARE NOTE
 *
 * The following software might be used in this product:
 *
 * OpenSSL Library, http://openssl-library.org/
 * Read THIRD-PARTY-LICENSES.txt or visit: http://openssl-library.org/source/license/index.html
 *
 * SQLite Library, http://www.sqlite.org/
 * Read THIRD-PARTY-LICENSES.txt or visit: https://www.sqlite.org/copyright.html
 *************************************************************************************************/

#ifndef SNMRTLIB_HH_
#define SNMRTLIB_HH_

#include "snmnslib.hh"
#include "snmgmlib.hh"
#include "eventinf.hh"

#define SQL_ERRORS_THRESHOLD_ALARM 100 // Alarm SQL errors threshold value
#define SQL_ERRORS_THRESHOLD_ABORT 200 // Abort program SQL errors threshold value
#define MAX_VENDOR_ID_LEN 20
#define DB_BACKUP_SLEEP_TIME 250 // in milliseconds

// Class 'RuntimeControl' declaration
class RuntimeControl
{
private:
	std::atomic<bool> _runFlag = {true}, _backupFlag = {false};
	std::mutex exit_mtx;
	std::string help;
	class GMonitor *gM;
	class httpSNMserver *nS;
	class snmMailer *smtph;
	class eventInformer *ei;
private:
	// Help info generator
	const std::string helpInfo(bool ipv6Enabled);
	// Keyboard input processing
	void onEnter();
	// Runtime errors processing
	void onError();
	// Backup database
	void backupDb(const char *zFilename, bool verbose);
public:
	// Constructor
	RuntimeControl(class GMonitor *gMonitor, class httpSNMserver *httpServer, class snmMailer *smtpHdlr, class eventInformer *eventInf);
	// Used as a barrier
	void exitControl();
};

#endif /* SNMRTLIB_HH_ */
