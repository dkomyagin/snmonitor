//======================================================================================
// Name        : snmonitor.cpp
// Author      : Dmitry Komyagin
// Version     : 2.25
// Created on  : Nov 8, 2024
// Copyright   : Public domain
// Description : SNMONITOR main project file, Linux, ISO C++14
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

using namespace std;

#include "snmonitor.h"
#include "snmgmlib.hh"
#include "snmrtlib.hh"
#include "snminitlib.hh"
#include "snmeventinf.hh"

int main( int argc, char* argv[] )
{
	int rc;
	struct initVars initv;
	static sqlite3 *db;
	string initFile = string(argv[0]) + ".ini";
	char cwd[PATH_MAX];

	cout << "snmonitor <" << APP_VERSION << ">" << " PID: " <<  getpid() << endl;

	// Check process privileges
	if(geteuid() != 0)
	{
		cerr << "This program requires root privileges" << endl;
		coutHelpMessage();
		return EXIT_SUCCESS;
	}
	// Termination handling
	at_quick_exit( [] {sqlite3_close(db);} );

	struct sigaction action = {0}, old_action = {0};
	action.sa_handler = [](int) {quick_exit(0);};

	sigaction(SIGINT, NULL, &old_action);
	if(old_action.sa_handler != SIG_IGN) sigaction(SIGINT, &action, NULL); // Ctrl-C
	sigaction(SIGHUP, NULL, &old_action);
	if(old_action.sa_handler != SIG_IGN) sigaction(SIGHUP, &action, NULL); // close terminal
	sigaction(SIGTERM, NULL, &old_action);
	if(old_action.sa_handler != SIG_IGN) sigaction(SIGTERM, &action, NULL); // kill process

	// Check option -h
	if(argc > 1)
	{
		// Search for "-h" option
		if(searchOptions(argc, argv, "-h") != -1)
		{
			coutHelpMessage();
			return EXIT_SUCCESS;
		}
	}
	// Process init file
	initFileProc(initFile, &initv);
	// Process command line
	switch( clProc(argc, argv, &initv, MAIN_DB_FILENAME) )
	{
		case -1: return EXIT_FAILURE;
		case  1: return EXIT_SUCCESS;
	}

	// debug
	/*
	cout << "\nInit:\n";
	cout << "Notify: " << initv.notify << endl;
	cout << "IPv6: " << initv.ipv6 << endl;
	cout << "HTTP port: " << initv.httpPort << endl;
	cout << "SMTP verbose: " << (int) initv.smtpVerbose << endl;
	if(initv.notify)
	{
		cout << "Srv: " << initv.smtpData.srv << endl;
		cout << "Port: " << initv.smtpData.port << endl;
		cout << "Sender: " << initv.smtpData.sndr << endl;
		cout << "Recipients: " << initv.smtpData.rcpts << endl;
		cout << "TLS: " << initv.smtpData.tls << endl;
		cout << "Verify: " << initv.smtpData.verify << endl;
		cout << "Username: " << initv.smtpData.username << endl;
		cout << "Password: " << initv.smtpData.password << endl;
	}
	cout << endl;
	*/

	// Set working directory
	if(getcwd( cwd, sizeof(cwd) ) != NULL)
	{
		cout << "Current working directory: " << cwd << endl;
	}
	else
	{
		perror("Unable to get current working directory");
		return EXIT_FAILURE;
	}
	// Initialize database
	rc = initDB(MAIN_DB_FILENAME, &db);
	if(rc != SQLITE_OK)
	{
		cerr << "Database initializing failure, rc = " << rc << endl;
		return EXIT_FAILURE;
	}
	// Start notification service
	bool smtpHdlrStarted = false;
	class snmMailer *snmMlr;

	if(initv.notify)
	{
		snmMlr = new snmMailer(initv.smtpData, initv.smtpVerbose);
	    if( snmMlr->isStarted() )
	    {
	    	smtpHdlrStarted = true;
	    	cout << "Notification service started\n";
	    }
	    else
	    {
	    	delete(snmMlr);
	    	snmMlr = nullptr;
	    	cout << "Notification service NOT started\n";
	    }
	}
	else
	{
		snmMlr = nullptr;
		cout << "Notification service disabled\n";
	}
	// Event information handler
	class eventInformer *evInfr = new snmInformer(snmMlr);
	// Start GMonitor
	class GMonitor *gMonitor = new GMonitor(db, evInfr, initv.ipv6);
	// Start HTTP server
	const html_pages_t sitePages =
	{
		{ "/", {homePage, 600} },
		{ "/site.webmanifest", {webManifest, 0} },
		{ HTML_INFO_PATH, {infoPage, 0} },
		{ HTML_MAIN_VIEW_SHORT_PATH, {viewPage, 0} },
		{ HTML_MAIN_VIEW_PATH, {viewPage, 0} },
		{ HTML_MAIN_VIEW_EXT_PATH, {viewPage, 0} },
		{ HTML_MAIN_VIEW_FULL_PATH, {viewPage, 0} },
		{ HTML_IPV6_VIEW_PATH, {viewPage, 0} },
		{ HTML_UNKNOWN_HOSTS_PATH, {viewPage, 0} },
		{ HTML_DHCP_HOSTS_PATH, {viewPage, 0} },
		{ HTML_NOTIFICATION_PATH, {smtpPage, 0} },
		{ IMG_FAVICON_PATH, {imgLoader, 0} },
		{ IMG_APPLE_TOUCH_PATH, {imgLoader, 0} },
		{ IMG_FAVICON16_PATH, {imgLoader, 0} },
		{ IMG_FAVICON32_PATH, {imgLoader, 0} },
		{ IMG_ANDROID512_PATH, {imgLoader, 0} },
		{ IMG_ANDROID192_PATH, {imgLoader, 0} }
	};

	bool httpSrvStarted;
	class httpSNMserver *httpServer;

	if(initv.httpPort)
	{
		httpServer = new httpSNMserver(gMonitor, snmMlr, initv.httpPort, sitePages, evInfr);
		httpSrvStarted = httpServer->isStarted();
	}
	else
	{
		// Note: http server disabled if port == 0
		httpServer = nullptr;
		httpSrvStarted = true;
		cout << "HTTP server disabled\n";
	}
	// Start runtime control
	if(gMonitor->isStarted() and httpSrvStarted)
	{
		class RuntimeControl rtCtrl(gMonitor, httpServer, snmMlr, evInfr);
		rtCtrl.exitControl();
	}

	cout << "Terminating\n";

	if(initv.httpPort) delete(httpServer);
	delete(gMonitor);
	sqlite3_close(db);
	if(smtpHdlrStarted) delete(snmMlr);
	delete(evInfr);

	cout << "Finished\n";
	return EXIT_SUCCESS;
}
