//======================================================================================
// Name        : snmrtlib.cpp
// Author      : Dmitry Komyagin
// Version     : 0.83
// Created on  : Dec 3, 2024
// Copyright   : Public domain
// Description : SNMONITOR RuntimeControl library, Linux, ISO C++14
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

#include "snmonitor.h"
#include "snmrtlib.h"
#include "snmrtlib.hh"

using namespace std;

// Output statistics to console
// Note: days == 0 - show all records
static void coutView(sqlite3 *db, char suf, uint8_t days = 0)
{
	sqlite3_stmt* stmt;
	int rc;
	char *txt;
	uint16_t l;
	uint8_t col;
	stringstream ss;
	string tbl, query;
	array<string, 11> mainViewRow;
	vector< array<string, 11> > mainViewArr;
	uint16_t maxlen[11];

	switch(suf)
	{
	case 's':
		tbl = "MAIN_VIEW_SHORT";
		mainViewRow = {"Update time (UTC)", "MAC address", "IPv4 address", "DNS name", "NBNS name", "mDNS name", "DHCP name"};
		break;
	case 'e':
		tbl = "MAIN_VIEW_EXT";
		mainViewRow = {"Update time (UTC)", "MAC address", "IPv4 address", "DNS name", "NBNS name", "mDNS name", "UPnP info", "DHCP name", "Vendor"};
		break;
	case 'f':
		tbl = "MAIN_VIEW_FULL";
		mainViewRow = {"Update time (UTC)", "MAC address", "IPv4 address", "DNS name", "NBNS name", "mDNS name", "UPnP info", "LLDP name", "DHCP name", "LLMNR name", "Vendor"};
		break;
	case 'm':
		tbl = "MAIN_VIEW";
		mainViewRow = {"Update time (UTC)", "MAC address", "IPv4 address", "DNS name", "NBNS name", "mDNS name", "DHCP name", "Vendor"};
		break;
	case 'u':
		tbl = "UNKNOWN_HOSTS_VIEW";
		mainViewRow = {"Update time (UTC)", "MAC address", "IPv4 address", "Vendor"};
		break;
	case 'd':
		tbl = "DHCP_VIEW";
		mainViewRow = {"MAC address", "Update time (UTC)", "Entry time (UTC)", "Host name", "Vendor identifier", "DHCP requested parameters", "DHCP options"};
		break;
	case 'v':
		tbl = "IPV6_VIEW";
		mainViewRow = {"Update time (UTC)", "MAC address", "IPv6 address", "If", "IPv4 address", "DNS name", "mDNS name", "LLMNR name", "Vendor"};
		break;
	default:
		tbl = "MAIN_VIEW";
		mainViewRow = {"Update time (UTC)", "MAC address", "IPv4 address", "DNS name", "NBNS name", "mDNS name", "DHCP name", "Vendor"};
	}
	mainViewArr.push_back(mainViewRow);
	col = mainViewRow.size();
	for(auto r:mainViewRow) if( r.empty() ) col--; // exclude empty columns

	query = "SELECT * FROM " + tbl;
	if(days) query += " WHERE updated > datetime('now','-" + to_string(days) + " day')";

	sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, NULL);

	for(uint8_t i = 0; i < col; i++)
		maxlen[i] = mainViewRow[i].length();

	while( ( rc = sqlite3_step(stmt) ) == SQLITE_ROW )
	{
		for(uint8_t i = 0; i < col; i++)
		{
			txt = (char *) sqlite3_column_text(stmt, i);
			mainViewRow[i] = txt == nullptr ? "" : txt  ;
			l = mainViewRow[i].length();
			if( (tbl == "DHCP_VIEW") and (i == 4) and (l > (MAX_VENDOR_ID_LEN + 3) ) ) // Vendor identifier can be up to 255 characters
			{
				l = MAX_VENDOR_ID_LEN;
				mainViewRow[i].resize(l);
				mainViewRow[i] += "...";
				l += 3;
			}
			if(maxlen[i] < l) maxlen[i] = l;
		}
		mainViewArr.push_back(mainViewRow);
	}

	//release resources
	sqlite3_finalize(stmt);

	ss << endl;
	for(auto it:mainViewArr)
	{
		for(uint8_t i = 0; i < col; i++)
			ss << setw(maxlen[i] + ( i < (col -1) ? 2 : 0 ) ) << left << it[i];
		ss << endl;
	}
	ss << "Total records: " << mainViewArr.size() - 1;
	if(days) ss << " updated for the last " << (int) days << ( (days == 1) ? " day" : " days" );
	ss << endl;
	cout << ss.str();
	return;
}
// Class 'RuntimeControl' methods

// Constructor
RuntimeControl::RuntimeControl(GMonitor *gMonitor, httpSNMserver *httpServer, snmMailer *smtpHdlr, eventInformer *eventInf)
{
	const struct eventData evdata = {SNM_RTC_MODULE_NAME, "RuntimeControl()", "RTC started\nUse 'h' + <Enter> for help", SNM_RTC_STARTED};
	gM = gMonitor;
	nS = httpServer;
	smtph = smtpHdlr;
	ei = eventInf;
	help = helpInfo( gM->isIPv6enabled() );

	thread keyControl(&RuntimeControl::onEnter, this);
	keyControl.detach();
	thread errControl(&RuntimeControl::onError, this);
	errControl.detach();

	// RTC started
	ei->onEvent(evdata);

	exit_mtx.lock();
}
// Help info generator
const string RuntimeControl::helpInfo(bool ipv6Enabled)
{
    stringstream ss;

    ss << "Commands:" << endl;
    ss << " - 'i' information" << endl;
    ss << " - 's' statistics" << endl;
    ss << " - 'q' quit" << endl;
    ss << " - 'p[1-9]' output short Main View [for the last n days]" << endl;
    ss << " - 'm[1-9]' output Main View [for the last n days]" << endl;
    ss << " - 'e[1-9]' output extended Main View [for the last n days]" << endl;
    if(ipv6Enabled)
    {
        ss << " - 'v[1-9]' output IPv6 view [for the last n days]" << endl;
    }
    ss << " - 'u[1-9]' output unknown hosts [for the last n days]" << endl;
    ss << " - 'd[1-9]' output DHСP records [for the last n days]" << endl;
    ss << " - 'w' HTTP server information" << endl;
    ss << " - 'n' Notification service information" << endl;
    ss << " - 't' Send test email" << endl;
    ss << " - 'b' backup database to '" << BACKUP_DB_FILENAME << "'" << endl;

    return ss.str();
}
// Used as a barrier
void RuntimeControl::exitControl()
{
	exit_mtx.lock();
	return;
}
// Keyboard input processing
void RuntimeControl::onEnter()
{
	string s;
	uint8_t days;
    while(_runFlag)
    {
    	cin >> s;
    	days = ch2int(s[1]); // days limit
    	switch( tolower(s[0]) )
    	{
    		case 'q':				// terminate when "q" is pressed
    			_runFlag = false;
    			break;
    		case 's':				// output statistics
    			gM->coutStatistics();
    			break;
    		case 'i':				// output info
    			gM->coutInfo();
    			break;
    		case 'p':				// output short MainView
    			coutView(gM->mdb, 's', days);
    			break;
    		case 'm':				// output MainView
    			coutView(gM->mdb, 'm', days);
    			break;
    		case 'e':				// output extended MainView
    			coutView(gM->mdb, 'e', days);
    			break;
    		case 'f':				// output full MainView
    		    coutView(gM->mdb, 'f', days);
    		    break;
    		case 'v':				// output IPv6 view
    			if( gM->isIPv6enabled() )
    				coutView(gM->mdb, 'v', days);
    			else
    				cout << "IPv6 is not enabled\n";
    		    break;
    		case 'u':				// output Unknown hosts view
    		    coutView(gM->mdb, 'u', days);
    		    break;
    		case 'd':				// output DHCP records view
    		    coutView(gM->mdb, 'd', days);
    		    break;
    		case 'n':				// Notification service
    			if(smtph != nullptr)
    				smtph->coutStats();
    			else
    				cout << "Notification service disabled\n";
    			break;
    		case 't':				// Send a test email
    			if(smtph != nullptr)
    			{
    				smtph->sendTestMail();
    				cout << getLocalTime() + "  Notification test email was queued\n";
    			}
    			else
    				cout << "Notification service disabled\n";
    		    break;
    		case 'w':				// output HTTP server info
    			if(nS != nullptr)
    				nS->coutInfo();
    			else
    				cout << "HTTP server disabled\n";
    		    break;
    		case 'b':				// run backup job
    			if(_backupFlag)
    			{
    				cout << "Backup job already running\n";
    			}
    			else
    			{
    				_backupFlag = true;
					thread dbBackup(&RuntimeControl::backupDb, this, BACKUP_DB_FILENAME, true); // true to show completion
    				dbBackup.detach();
    			}
    			break;
    		default:
    			cout << help;
    			break;
    	}
    }
    exit_mtx.unlock();
    return;
}
// Runtime errors processing
void RuntimeControl::onError()
{
	// e1 - services init errors
	// e2 - helpers init errors
	// e3 - getInterfaces error
	// e4 = SQL errors
	short e1, e2, e3;
	uint64_t e4;
	struct eventData evdata = {SNM_RTC_MODULE_NAME, "onError()", "", 0};
	bool mssg_sent = false;

	while(_runFlag)
	{
		tie(e1, e2, e3, e4) = gM->checkExecErrors();
		if( e1 or e2 or e3 or (e4 > SQL_ERRORS_THRESHOLD_ABORT) )
		{
			if(e1 != -1) // Shutdown already started when e1 == -1
			{
				stringstream ss;
				ss << "Critical errors detected, stopping. ";
				ss << "Service init errors: " << e1;
				ss << ", helper init errors: " << e2;
				ss << ", interface errors: " << e3;
				ss << ", SQL errors: " << e4;
				evdata.message = ss.str();
				evdata.type = SNM_RTC_CRITICAL_ERROR;
				ei->onEvent(evdata);
				break;
			}
		}
		if( !mssg_sent and (e4 > SQL_ERRORS_THRESHOLD_ALARM) )
		{
			evdata.message = "SQL errors threshold violation. SQL errors: " + to_string(e4);
			evdata.type = SNM_RTC_SQL_ERR_ALARM;
			ei->onEvent(evdata);
			mssg_sent = true;
		}
	}
	_runFlag = false;
	exit_mtx.unlock();
	return;
}
// Backup database
void RuntimeControl::backupDb(const char *zFilename, bool verbose)
{
	int src, drc;
	sqlite3 *pFile;             // Destination database connection opened on zFilename
	sqlite3_backup *pBackup;    // Source backup handle used to copy data
	stringstream ss;
	uint16_t cmpl, pcnt, rcnt; //Completion = 100% * (pagecount() - remaining()) / pagecount()
	uint8_t last = 0;

	// Open the database file identified by zFilename
	src = sqlite3_open( zFilename, &pFile );
	if( src == SQLITE_OK )
	{
		ss << "Database backup job started at " << getLocalTime() << endl;
		cout << ss.str();
		// Open the sqlite3_backup object used to accomplish the transfer
		pBackup = sqlite3_backup_init(pFile, "main", gM->mdb, "main");
		if(pBackup)
		{
			// Each iteration of this loop copies 5 database pages from database
			// pDb to the backup database. If the return value of backup_step()
			// indicates that there are still further pages to copy, sleep for
			// DB_BACKUP_SLEEP_TIME (in ms) before repeating.
			do
			{
				if(!_runFlag)
				{
					src = SQLITE_ABORT;
					break;
				}
				src = sqlite3_backup_step( pBackup, 5 );
				if(!_runFlag)
				{
					src = SQLITE_ABORT;
					break;
				}
				pcnt = sqlite3_backup_pagecount(pBackup);
				rcnt = sqlite3_backup_remaining(pBackup);
				cmpl = (pcnt != 0) ? 100*(pcnt - rcnt)/pcnt : 0;
				if( verbose and (cmpl%10 == 0) and (cmpl != last) ) // cmpl != last - to prevent outputting the same numbers
				{
					last = cmpl;
					ss.str("");
					ss << "Database backup completion: " << cmpl << "%" << endl;
					cout << ss.str();
				}
				if(src==SQLITE_OK || src==SQLITE_BUSY || src==SQLITE_LOCKED)
				{
					sqlite3_sleep(DB_BACKUP_SLEEP_TIME);
				}
			} while(src==SQLITE_OK || src==SQLITE_BUSY || src==SQLITE_LOCKED);

			// Release resources allocated by backup_init()
			sqlite3_backup_finish(pBackup);
		}
		drc = sqlite3_errcode(pFile); // error code from destination database
	}
	else
	{
		sqlite3_close(pFile);
		ss << "Database backup job failure, rc = " << src << endl;
		cout << ss.str();
		_backupFlag = false;
		return;
	}
	// Close the database connection opened on database file zFilename
	// and return the result of this function
	sqlite3_close(pFile);
	if( src == SQLITE_ABORT )
		cout << "Database backup job aborted\n";
	else if(src == SQLITE_DONE && drc == SQLITE_OK)
	{
		ss.str("");
		ss << "Database backup job finished successfully at " << getLocalTime() << endl;
		cout << ss.str();
	}
	else
	{
		ss.str("");
		ss << "Database backup job failure, source rc = " << src << ", destination rc = " << drc << endl;
		cout << ss.str();
	}
	_backupFlag = false;
	return;
}
