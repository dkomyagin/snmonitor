//======================================================================================
// Name        : snminitlib.hh
// Author      : Dmitry Komyagin
// Version     : 0.5
// Created on  : Oct 16, 2024
// Copyright   : Public domain
// Description : Header file for SNMONITOR init library, Linux, ISO C++14
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

#ifndef SNMINITLIB_HH_
#define SNMINITLIB_HH_

#include "snmonitor.h"
#include "smtp.hh"
#include "snmdblib.hh"
#include <fstream>

typedef std::map<std::string, std::string> dict;
typedef std::map<std::string, dict> cfgdict;
//
struct initVars
{
	bool notify = false;
	bool ipv6   = false;
	in_port_t httpPort  = APP_DEFAULT_HTTP_PORT;
	uint8_t smtpVerbose = SMTP_DEFAULT_VERBOSE_LVL;
	struct smtpParams smtpData;
};

// Output help message to console
void coutHelpMessage();
// Search in options
int searchOptions(int argc, char* argv[], const char *opt);
// Init file processing
int initFileProc(std::string initFile, struct initVars *initv);
// Command line processing
// Return code: '-1' - terminate with EXIT_FAILURE; '0' - OK, go ahead; '1' - terminate with EXIT_SUCCESS
int clProc(int argc, char* argv[], struct initVars *initv, const char *db_file_name);

#endif /* SNMINITLIB_HH_ */
