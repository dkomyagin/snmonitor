//============================================================================
// Name        : snmdblib.cpp
// Author      : Dmitry Komyagin
// Version     : 1.01
// Created on  : Oct 27, 2024
// Copyright   : Public domain
// Description : SNMONITOR DBM library, Linux, ISO C++14
//============================================================================

/*************************************************************************************************
 * THIRD-PARTY SOFTWARE NOTE
 *
 * The following software might be used in this product:
 *
 * SQLite Library, http://www.sqlite.org/
 * Read THIRD-PARTY-LICENSES.txt or visit: https://www.sqlite.org/copyright.html
 *************************************************************************************************/

#include "snmdblib.h"
#include "snmdblib.hh"
#include "snmcommlib.hh"

using namespace std;

#ifndef NETBIOS_NAME_LEN
#define NETBIOS_NAME_LEN 16
#endif

//
static string mssg2string(char *mssg)
{
	if(mssg)
		return string(mssg);
	else
		return "no message provided";
}
//
static int createTable(sqlite3 *db, const char *table_name, const char *table_columns)
{
	int rc;
	char *zErrMsg = 0;
	stringstream sqlmsg;
	string sqlMessage;

	sqlmsg << "CREATE TABLE IF NOT EXISTS " << table_name << "(";
	sqlmsg << table_columns << ");";

	sqlMessage = sqlmsg.str();

	rc = sqlite3_exec(db, sqlMessage.c_str(), NULL, 0, &zErrMsg);

	if(rc != SQLITE_OK)
	{
		cerr << "createTable(): SQL error: " << zErrMsg << endl;
		sqlite3_free(zErrMsg);
	}

	return rc;
}
//
static int createView(sqlite3 *db, const char *view_name, const char *view_message)
{
	int rc;
	char *zErrMsg = 0;
	stringstream sqlmsg;
	string sqlMessage;

	sqlmsg << "CREATE VIEW IF NOT EXISTS " << view_name << " AS ";
	sqlmsg << view_message;

	sqlMessage = sqlmsg.str();

	rc = sqlite3_exec(db, sqlMessage.c_str(), NULL, 0, &zErrMsg);

	if(rc != SQLITE_OK)
	{
		cerr << "createView(): SQL error: " << zErrMsg << endl;
		sqlite3_free(zErrMsg);
	}

	return rc;
}
//
int uploadMACvendors(sqlite3 *db, const char *csvFileName, bool verbose)
{
	int tr = 0, ur = 0, sr = 0, rc;
	string line, vendor;
	sqlite3_stmt* stmt;
	char *zErrMsg = nullptr;
	smatch sm;
	unsigned sz;
	array<string, 5> values;
	bool qm;

	ifstream ifs(csvFileName, std::ifstream::in); // Open csv file
	if (!ifs.fail() )
	{
		rc = sqlite3_prepare_v2( db, "INSERT INTO MAC_VENDORS VALUES(?1,?2,?3,?4,?5);", -1, &stmt, NULL );
		if(rc != SQLITE_OK)
		{
			cerr << "uploadMACvendors(): SQL prepare error" << endl;
			return SQLITE_ERROR;
		}
		rc = sqlite3_exec( db, "BEGIN;", NULL, 0, &zErrMsg ); // Begin transaction
		if(rc != SQLITE_OK)
		{
			cerr << "uploadMACvendors(): begin SQL error: " << zErrMsg << endl;
			sqlite3_free(zErrMsg);
			return SQLITE_ERROR;
		}
		sqlite3_exec( db, "DELETE FROM MAC_VENDORS;", NULL, 0, &zErrMsg ); // Not done before commit
		if(rc != SQLITE_OK)
		{
			cerr << "uploadMACvendors(): Unable to delete MAC_VENDORS table SQL error: " << zErrMsg << endl;
			sqlite3_free(zErrMsg);
			rc = sqlite3_exec( db, "ROLLBACK;", NULL, 0, &zErrMsg );
			if(rc != SQLITE_OK)
			{
				cerr << "uploadMACvendors(): rollback SQL error: " << zErrMsg << endl;
				sqlite3_free(zErrMsg);
			}
			return SQLITE_ERROR;
		}

		regex e = regex("(\\w{2}:\\w{2}:\\w{2}:?\\w{0,2}:?\\w{0,2}),(.*),(false|true),(.*),(.+)"); // line parsing expression

		getline(ifs, line); // skip legend
		while( getline(ifs, line) )
		{
			tr++;
			if( regex_match(line, sm, e) )
			{
				sz = sm.size();
				for(unsigned j = 1; j < sz; ++j)
				{
					values[j - 1] = sm[j].str();
					if(j == 2)
					{
						vendor = ""; qm = false;
						for(char c:values[j - 1])
						{
							if( (c == '"') and not qm )
							{
								qm = true;
							}
							else
							{
								qm = false;
								vendor += c;
							}
						}
						values[j - 1] = vendor;
					}
					rc = sqlite3_bind_text(stmt, j, values[j -1].c_str(), values[j -1].size(), NULL);
					if(rc != SQLITE_OK)
					{
						cerr << "uploadMACvendors(): SQL bind error" << endl;
						rc = sqlite3_exec(db, "ROLLBACK;", NULL, 0, &zErrMsg);
						if(rc != SQLITE_OK)
						{
							cerr << "uploadMACvendors(): rollback SQL error: " << zErrMsg << endl;
							sqlite3_free(zErrMsg);
						}
						return SQLITE_ERROR;
					}
				}
				rc = sqlite3_step(stmt);
				sqlite3_reset(stmt);
				if(rc == SQLITE_CONSTRAINT)
				{
					++sr;
					if(verbose) cerr << "Duplicate MAC address at line: " << (tr + 1) << endl;
					continue;
				}
				if(rc != SQLITE_DONE)
				{
					cerr << "uploadMACvendors(): step SQL error" << endl;
					rc = sqlite3_exec(db, "ROLLBACK;", NULL, 0, &zErrMsg);
					if(rc != SQLITE_OK)
					{
						cerr << "uploadMACvendors(): rollback SQL error: " << zErrMsg << endl;
						sqlite3_free(zErrMsg);
					}
					return SQLITE_ERROR;
				}
				ur++;
			}
			else
			{
				if(verbose) cerr << "Error parsing file " << csvFileName << " at line: " << (tr + 1) << endl;
				++sr;
				continue;
			}
		}
		ifs.close(); //close file
	}
	else
	{
		cerr << "Error reading file: '" << csvFileName << "'" << endl;
		return -1;
	}
	rc = sqlite3_exec(db, "COMMIT;", NULL, 0, &zErrMsg); // Commit
	if(rc != SQLITE_OK)
	{
		cerr << "uploadMACvendors(): commit SQL error: " << zErrMsg << endl;
		sqlite3_free(zErrMsg);
		rc = sqlite3_exec(db, "ROLLBACK;", NULL, 0, &zErrMsg);
		if(rc != SQLITE_OK)
		{
			cerr << "uploadMACvendors(): rollback SQL error: " << zErrMsg << endl;
			sqlite3_free(zErrMsg);
		}
		return SQLITE_ERROR;
	}
	sqlite3_finalize(stmt);
	cout << "Total records: " << tr << ", uploaded: " << ur << ", skipped: " << sr << endl;
	return SQLITE_OK;
}
//
int initDB(const char *filename, sqlite3 **db)
{
	int rc;
	char *zErrMsg = nullptr;
	// Open database
	rc = sqlite3_open(filename, db);
	if(rc != SQLITE_OK)
	{
		cerr << "Cannot open or create file: " << filename << ", " << sqlite3_errmsg( *db ) << endl;
	    return rc;
	}
	else
	{
		cout << "Database has been opened successfully\n";
	}
	// Set journal mode
	sqlite3_exec(*db, "PRAGMA journal_mode = PERSIST;", NULL, 0, NULL);
	// Set locking mode
	sqlite3_exec(*db, "PRAGMA locking_mode = EXCLUSIVE;", NULL, 0, &zErrMsg);
	if(rc != SQLITE_OK)
	{
		cerr << "Unable to set locking mode: " << zErrMsg << endl;
		sqlite3_free(zErrMsg);
		return rc;
	}
	// Create tables
	// Create table 'ARP'
	const char *ARP_columns = "mac TEXT PRIMARY KEY NOT NULL, mac_upd_ts TEXT NOT NULL, " \
							  "mac_add_ts TEXT NOT NULL, ipv4 TEXT, ipv4_upd_ts TEXT";
	rc = createTable(*db, "ARP", ARP_columns);
	if(rc != SQLITE_OK)
	{
		sqlite3_close(*db);
		return rc;
	}
	// Create table 'DNS'
	const char *DNS_columns = "mac TEXT PRIMARY KEY NOT NULL, host_name TEXT NOT NULL, " \
							  "host_upd_ts TEXT NOT NULL, host_add_ts TEXT NOT NULL";
	rc = createTable(*db, "DNS", DNS_columns);
	if(rc != SQLITE_OK)
	{
		sqlite3_close(*db);
		return rc;
	}
	// Create table 'DNS_JOURNAL'
	const char *DNS_JOURNAL_columns = "mac TEXT NOT NULL, host_name TEXT, " \
									  "prev_name TEXT, record_ts TEXT NOT NULL";
	rc = createTable(*db, "DNS_JOURNAL", DNS_JOURNAL_columns);
	if(rc != SQLITE_OK)
	{
		sqlite3_close(*db);
		return rc;
	}
	// Create table 'NBNS'
	const char *NBNS_columns = "mac TEXT PRIMARY KEY NOT NULL, host_name TEXT NOT NULL, " \
							   "host_upd_ts TEXT NOT NULL, host_add_ts TEXT NOT NULL";
	rc = createTable(*db, "NBNS", NBNS_columns);
	if(rc != SQLITE_OK)
	{
		sqlite3_close(*db);
		return rc;
	}
	// Create table 'NBNS_JOURNAL'
	const char *NBNS_JOURNAL_columns = "mac TEXT NOT NULL, host_name TEXT NOT NULL, " \
									   "prev_name TEXT NOT NULL, record_ts TEXT NOT NULL";
	rc = createTable(*db, "NBNS_JOURNAL", NBNS_JOURNAL_columns);
	if(rc != SQLITE_OK)
	{
		sqlite3_close(*db);
		return rc;
	}
	// Create table 'MDNS'
	const char *MDNS_columns = "mac TEXT PRIMARY KEY NOT NULL, host_name TEXT NOT NULL, " \
							   "host_upd_ts TEXT NOT NULL, host_add_ts TEXT NOT NULL";
	rc = createTable(*db, "MDNS", MDNS_columns);
	if(rc != SQLITE_OK)
	{
		sqlite3_close(*db);
		return rc;
	}
	// Create table 'MDNS_JOURNAL'
	const char *MDNS_JOURNAL_columns = "mac TEXT NOT NULL, host_name TEXT NOT NULL, " \
									   "prev_name TEXT NOT NULL, record_ts TEXT NOT NULL";
	rc = createTable(*db, "MDNS_JOURNAL", MDNS_JOURNAL_columns);
	if(rc != SQLITE_OK)
	{
		sqlite3_close(*db);
		return rc;
	}
	// Create table 'UPNP'
	const char *UPNP_columns = "mac TEXT PRIMARY KEY NOT NULL, device_description TEXT NOT NULL, "	\
							   "device_upd_ts TEXT NOT NULL, device_add_ts TEXT NOT NULL, " 		\
							   "url TEXT NOT NULL";
	rc = createTable(*db, "UPNP", UPNP_columns);
	if(rc != SQLITE_OK)
	{
		sqlite3_close(*db);
		return rc;
	}
	// Create table 'UPNP_JOURNAL'
	const char *UPNP_JOURNAL_columns = "mac TEXT NOT NULL, device_description TEXT NOT NULL, "		\
									   "urn TEXT NOT NULL, prev_device_description TEXT NOT NULL, "	\
									   "prev_urn TEXT NOT NULL, record_ts TEXT NOT NULL";
	rc = createTable(*db, "UPNP_JOURNAL", UPNP_JOURNAL_columns);
	if(rc != SQLITE_OK)
	{
		sqlite3_close(*db);
		return rc;
	}
	// Create table 'LLDP'
	const char *LLDP_columns = "mac TEXT PRIMARY KEY NOT NULL, system_name TEXT NOT NULL, " \
							   "name_upd_ts TEXT NOT NULL, name_add_ts TEXT NOT NULL";
	rc = createTable(*db, "LLDP", LLDP_columns);
	if(rc != SQLITE_OK)
	{
		sqlite3_close(*db);
		return rc;
	}
	// Create table 'LLDP_JOURNAL'
	const char *LLDP_JOURNAL_columns = "mac TEXT NOT NULL, system_name TEXT NOT NULL, " \
									   "prev_name TEXT NOT NULL, record_ts TEXT NOT NULL";
	rc = createTable(*db, "LLDP_JOURNAL", LLDP_JOURNAL_columns);
	if( rc != SQLITE_OK )
	{
		sqlite3_close(*db);
		return rc;
	}
	// Create table 'LLMNR'
	const char *LLMNR_columns = "mac TEXT PRIMARY KEY NOT NULL, host_name TEXT NOT NULL, " \
							    "host_upd_ts TEXT NOT NULL, host_add_ts TEXT NOT NULL";
	rc = createTable(*db, "LLMNR", LLMNR_columns);
	if(rc != SQLITE_OK)
	{
		sqlite3_close(*db);
		return rc;
	}
	// Create table 'LLMNR_JOURNAL'
	const char *LLMNR_JOURNAL_columns = "mac TEXT NOT NULL, host_name TEXT NOT NULL, " \
									    "prev_name TEXT NOT NULL, record_ts TEXT NOT NULL";
	rc = createTable(*db, "LLMNR_JOURNAL", LLMNR_JOURNAL_columns);
	if(rc != SQLITE_OK)
	{
		sqlite3_close(*db);
		return rc;
	}
	// Create table 'DHCPV4'
	const char *DHCPV4_columns = "mac TEXT PRIMARY KEY NOT NULL, host_name TEXT, "			\
							   	 "record_upd_ts TEXT NOT NULL, record_add_ts TEXT NOT NULL, "	\
								 "vendor_identifier TEXT, parameters TEXT, options TEXT";
	rc = createTable(*db, "DHCPV4", DHCPV4_columns);
	if(rc != SQLITE_OK)
	{
		sqlite3_close(*db);
		return rc;
	}
	// Create table 'DHCPV4_JOURNAL'
	const char *DHCPV4_JOURNAL_columns = "mac TEXT NOT NULL, host_name TEXT NOT NULL, " \
									   	 "prev_name TEXT NOT NULL, record_ts TEXT NOT NULL";
	rc = createTable(*db, "DHCPV4_JOURNAL", DHCPV4_JOURNAL_columns);
	if(rc != SQLITE_OK)
	{
		sqlite3_close(*db);
		return rc;
	}
	// Create table 'MESSAGE_LOG'
	const char *MESSAGE_LOG_columns = "timestamp TEXT NOT NULL, message TEXT NOT NULL";
	rc = createTable(*db, "MESSAGE_LOG", MESSAGE_LOG_columns);
	if(rc != SQLITE_OK)
	{
		sqlite3_close(*db);
		return rc;
	}
	// Create table 'MAC_VENDORS'
	const char *MAC_VENDORS_columns = "MacPrefix TEXT NOT NULL, VendorName TEXT NOT NULL, "	\
									  "Private TEXT, BlockType TEXT, LastUpdate TEXT";
	rc = createTable(*db, "MAC_VENDORS", MAC_VENDORS_columns);
	if(rc != SQLITE_OK)
	{
		sqlite3_close(*db);
		return rc;
	}
	// Create index on 'MAC_VENDORS'
	sqlite3_exec(*db, "CREATE UNIQUE INDEX IF NOT EXISTS mp_idx ON MAC_VENDORS(MacPrefix);", NULL, 0, NULL);
	// Create table 'IPV6'
	const char *IPV6_columns = "mac TEXT PRIMARY KEY NOT NULL, mac_upd_ts TEXT NOT NULL, " \
							   "mac_add_ts TEXT NOT NULL, ipv6_ll TEXT, if_num INTEGER, ipv6_upd_ts TEXT";
	rc = createTable(*db, "IPV6", IPV6_columns);
	if(rc != SQLITE_OK)
	{
		sqlite3_close(*db);
		return rc;
	}
	// Create views
	// Create 'MAIN_VIEW'
	sqlite3_exec(*db, "DROP VIEW IF EXISTS MAIN_VIEW;", NULL, 0, NULL);
	const char * MAIN_VIEW_message = "SELECT mac_upd_ts AS updated, mac, "					\
									 "ipv4, DNS.host_name AS dns_name, "					\
									 "NBNS.host_name AS nbns_name, "						\
									 "MDNS.host_name AS mdns_name, "						\
									 "DHCPV4.host_name AS dhcp_name, "						\
									 "MAC_VENDORS.vendorname AS vendor from ARP "			\
									 "LEFT JOIN DNS USING(mac) "							\
									 "LEFT JOIN NBNS USING(mac) "							\
									 "LEFT JOIN MDNS USING(mac) "							\
									 "LEFT JOIN DHCPV4 USING(mac) "							\
									 "LEFT JOIN MAC_VENDORS ON mac LIKE macprefix || '%' " 	\
									 "ORDER BY updated DESC;";
	rc = createView(*db, "MAIN_VIEW", MAIN_VIEW_message);
	if(rc != SQLITE_OK)
	{
		sqlite3_close(*db);
		return rc;
	}
	// Create 'MAIN_VIEW_EXT'
	sqlite3_exec(*db, "DROP VIEW IF EXISTS MAIN_VIEW_EXT;", NULL, 0, NULL);
	const char * MAIN_VIEW_EXT_message = "SELECT mac_upd_ts AS updated, mac, "					\
									 	 "ipv4, DNS.host_name AS dns_name, "					\
										 "NBNS.host_name AS nbns_name, "						\
										 "MDNS.host_name AS mdns_name, "						\
										 "UPNP.device_description AS device_description, "		\
										 "DHCPV4.host_name AS dhcp_name, "						\
										 "MAC_VENDORS.vendorname AS vendor from ARP "			\
										 "LEFT JOIN DNS USING(mac) "							\
										 "LEFT JOIN NBNS USING(mac) "							\
										 "LEFT JOIN MDNS USING(mac) "							\
										 "LEFT JOIN UPNP USING(mac) "							\
										 "LEFT JOIN DHCPV4 USING(mac) "							\
										 "LEFT JOIN MAC_VENDORS ON mac LIKE macprefix || '%' "	\
										 "ORDER BY updated DESC;";
	rc = createView(*db, "MAIN_VIEW_EXT", MAIN_VIEW_EXT_message);
	if(rc != SQLITE_OK)
	{
		sqlite3_close(*db);
		return rc;
	}
	// Create 'MAIN_VIEW_FULL'
	sqlite3_exec(*db, "DROP VIEW IF EXISTS MAIN_VIEW_FULL;", NULL, 0, NULL);
	const char * MAIN_VIEW_FULL_message = "SELECT mac_upd_ts AS updated, mac, "						\
									 	  "ipv4, DNS.host_name AS dns_name, "						\
										  "NBNS.host_name AS nbns_name, "							\
										  "MDNS.host_name AS mdns_name, "							\
										  "UPNP.device_description AS device_description, "			\
										  "LLDP.system_name AS lldp_name, "							\
										  "DHCPV4.host_name AS dhcp_name, "							\
										  "LLMNR.host_name AS llmnr_name, "							\
										  "MAC_VENDORS.vendorname AS vendor from ARP "				\
										  "LEFT JOIN DNS USING(mac) "								\
										  "LEFT JOIN NBNS USING(mac) "								\
										  "LEFT JOIN MDNS USING(mac) "								\
										  "LEFT JOIN UPNP USING(mac) "								\
										  "LEFT JOIN LLDP USING(mac) "								\
										  "LEFT JOIN DHCPV4 USING(mac) "							\
										  "LEFT JOIN LLMNR USING(mac) "								\
										  "LEFT JOIN MAC_VENDORS ON mac LIKE macprefix || '%' " 	\
	 	 	 	 	 	 	 	 	 	  "ORDER BY updated DESC;";
	rc = createView(*db, "MAIN_VIEW_FULL", MAIN_VIEW_FULL_message);
	if(rc != SQLITE_OK)
	{
		sqlite3_close(*db);
		return rc;
	}
	// Create 'MAIN_VIEW_SHORT'
	sqlite3_exec(*db, "DROP VIEW IF EXISTS MAIN_VIEW_SHORT;", NULL, 0, NULL);
	const char *MAIN_VIEW_SHORT_message = "SELECT mac_upd_ts AS updated, mac, "			\
										  "ipv4, DNS.host_name AS dns_name, "			\
										  "NBNS.host_name AS nbns_name, "				\
										  "MDNS.host_name AS mdns_name, "				\
										  "DHCPV4.host_name AS dhcp_name from ARP "		\
										  "LEFT JOIN DNS USING(mac) "					\
										  "LEFT JOIN NBNS USING(mac) "					\
										  "LEFT JOIN MDNS USING(mac) "					\
										  "LEFT JOIN DHCPV4 USING(mac) " 				\
	 	 	 	 	 	 	 	 	 	  "ORDER BY updated DESC;";
	rc = createView(*db, "MAIN_VIEW_SHORT", MAIN_VIEW_SHORT_message);
	if(rc != SQLITE_OK)
	{
		sqlite3_close(*db);
		return rc;
	}
	// Create 'UNKNOWN_HOSTS_VIEW'
	sqlite3_exec(*db, "DROP VIEW IF EXISTS UNKNOWN_HOSTS_VIEW;", NULL, 0, NULL);
	stringstream query;
	const char* rows[] = {"dns_name", "nbns_name", "mdns_name", "device_description", "lldp_name", "dhcp_name", "llmnr_name"};
	int len = sizeof(rows)/sizeof(rows[0]);
	query << "SELECT updated, mac, ipv4, vendor FROM MAIN_VIEW_FULL WHERE ";
	for( uint8_t n = 0; n < len; n++ )
	{
		query << "(" << rows[n] << " is null OR " << rows[n] << " = '') ";
		if( n != (len - 1) ) query << "AND ";
	}
	rc = createView( *db, "UNKNOWN_HOSTS_VIEW", query.str().c_str() );
	if(rc != SQLITE_OK)
	{
		sqlite3_close(*db);
		return rc;
	}
	// Create 'DHCP VIEW'
	sqlite3_exec(*db, "DROP VIEW IF EXISTS DHCP_VIEW;", NULL, 0, NULL);
	const char *DHCP_VIEW_message = "SELECT mac, record_upd_ts AS updated, record_add_ts AS added, " \
									"host_name, vendor_identifier, parameters, options FROM DHCPV4 " \
									"ORDER BY updated DESC;";
	rc = createView(*db, "DHCP_VIEW", DHCP_VIEW_message);
	if(rc != SQLITE_OK)
	{
		sqlite3_close(*db);
		return rc;
	}
	// Create 'IPV6_VIEW'
	sqlite3_exec(*db, "DROP VIEW IF EXISTS IPV6_VIEW;", NULL, 0, NULL);
	const char * IPV6_VIEW_message = "SELECT IPV6.mac_upd_ts AS updated, mac, "				\
									 "ipv6_ll AS ipv6, if_num, ARP.ipv4 AS ipv4, "			\
									 "DNS.host_name AS dns_name, "							\
									 "MDNS.host_name AS mdns_name, "						\
									 "LLMNR.host_name AS llmnr_name, "						\
									 "MAC_VENDORS.vendorname AS vendor from IPV6 "			\
									 "LEFT JOIN ARP USING(mac) "							\
									 "LEFT JOIN DNS USING(mac) "							\
									 "LEFT JOIN MDNS USING(mac) "							\
									 "LEFT JOIN LLMNR USING(mac) "							\
									 "LEFT JOIN MAC_VENDORS ON mac LIKE macprefix || '%' " 	\
									 "ORDER BY if_num ASC, updated DESC;";
	rc = createView(*db, "IPV6_VIEW", IPV6_VIEW_message);
	if(rc != SQLITE_OK)
	{
		sqlite3_close(*db);
		return rc;
	}
	return SQLITE_OK;
}
//
static string mtx_sqlite3_errmsg( sqlite3 *db )
{
	string errmsg;

	sqlite3_mutex_enter( sqlite3_db_mutex(db) );
    errmsg = sqlite3_errmsg(db);
	sqlite3_mutex_leave( sqlite3_db_mutex(db) );
	return errmsg;
}
//
string getURN(string url)
{
	return url.substr(url.find('/', 8) + 1);
}

// Class 'dbManager' methods
// Constructor
dbManager::dbManager(sqlite3 *database, eventInformer *eventInf)
{
	db = database;
	ei = eventInf;
}
// Message log
int dbManager::toDBMessageLog(string mssg)
{
	int rc;
	char *zErrMsg = nullptr;
	struct eventData edata = {SNM_DB_MODULE_NAME, "toDBMessageLog()", "", SNM_DB_SQL_ERROR};
	stringstream sqlmsg;
	string sqlMessage;

	sqlmsg << "INSERT into MESSAGE_LOG";
	sqlmsg << "(timestamp, message)";
	sqlmsg << " VALUES" << "(";
	sqlmsg << "datetime(),";
	sqlmsg << "'" << mssg << "'";
	sqlmsg << ");";
	sqlMessage = sqlmsg.str();

	for(uint8_t r = 0; r < MAX_RETRY_TRANSACTION; r++)
	{
		if(r != 0)
		{
			sqlite3_free(zErrMsg);
			this_thread::sleep_for(RETRY_TRANSACTION_TIME);
		}
		rc = sqlite3_exec(db, sqlMessage.c_str(), NULL, 0, &zErrMsg);
		if( (rc != SQLITE_BUSY) and (rc != SQLITE_LOCKED) ) break;
	}
	if(rc != SQLITE_OK)
	{
		edata.message = "SQL error: " + mssg2string(zErrMsg);
		ei->onEvent(edata);
		sqlite3_free(zErrMsg);
	}
	return rc;
}
//
int dbManager::callbackIPv4hosts(void *ipv4Hosts, int argc, char **argv, char **azColName)
{
	(*((unordered_set<in_addr_t> *) ipv4Hosts)).insert( inet_addr(argv[0]) );
	return 0;
}
//
int dbManager::getFreshIPv4hosts(unordered_set<in_addr_t> *ipv4Hosts)
{
	int rc;
	char *zErrMsg = nullptr;
	struct eventData edata = {SNM_DB_MODULE_NAME, "getFreshIPv4hosts()", "", SNM_DB_SQL_ERROR};
	const char *sql = "SELECT ipv4 FROM ARP WHERE ipv4_upd_ts > datetime('now', '-10 minutes') AND ipv4 != '';";

	rc = sqlite3_exec(db, sql, callbackIPv4hosts, ipv4Hosts, &zErrMsg);
	if(rc != SQLITE_OK)
	{
		edata.message = "SQL error: " + mssg2string(zErrMsg);
		ei->onEvent(edata);
		sqlite3_free(zErrMsg);
	}
	return rc;
}
//
int dbManager::getIPv4hosts(unordered_set<in_addr_t> *ipv4Hosts)
{
	int rc;
	char *zErrMsg = nullptr;
	struct eventData edata = {SNM_DB_MODULE_NAME, "getIPv4hosts()", "", SNM_DB_SQL_ERROR};
	const char *sql = "SELECT ipv4 FROM ARP WHERE ipv4 != '';";

	rc = sqlite3_exec(db, sql, callbackIPv4hosts, ipv4Hosts, &zErrMsg);
	if(rc != SQLITE_OK)
	{
		edata.message = "SQL error: " + mssg2string(zErrMsg);
		ei->onEvent(edata);
		sqlite3_free(zErrMsg);
	}
	return rc;
}
//
int dbManager::callbackIPv4MAC(void *macIPv4, int argc, char **argv, char **azColName)
{
	(*((map<string, string> *) macIPv4)).insert( make_pair( string(argv[0]), string(argv[1]) ) );

   return 0;
}
//
int dbManager::getFreshIPv4MAC(map<string, string> *macIPv4)
{
	int rc;
	char *zErrMsg = nullptr;
	struct eventData edata = {SNM_DB_MODULE_NAME, "getIPv4hosts()", "", SNM_DB_SQL_ERROR};
	const char *sql = "SELECT mac, ipv4 FROM ARP WHERE ipv4_upd_ts > datetime('now', '-10 minutes') AND ipv4 != '';";

	rc = sqlite3_exec(db, sql, callbackIPv4MAC, macIPv4, &zErrMsg);
	if(rc != SQLITE_OK)
	{
		edata.message = "SQL error: " + mssg2string(zErrMsg);
		ei->onEvent(edata);
		sqlite3_free(zErrMsg);
	}
	return rc;
}
// ARP
int dbManager::newARProw(const char *mac_addr, const char *ipv4_addr)
{
	int rc;
	char *zErrMsg = nullptr;
	struct eventData edata = {SNM_DB_MODULE_NAME, "newARProw()", "", 0};
	stringstream sqlmsg;
	string sqlMessage;
	string infoMessage = "New MAC address has been detected: ";

	sqlmsg << "INSERT OR ROLLBACK into ARP";
	if(ipv4_addr != nullptr)
	{
		sqlmsg << "(mac, mac_upd_ts, mac_add_ts, ipv4, ipv4_upd_ts)";
	}
	else
	{
		sqlmsg << "(mac, mac_upd_ts, mac_add_ts)";
	}
	sqlmsg << " VALUES" << "(";
	sqlmsg << "'" << mac_addr << "'" << ",";
	sqlmsg << "datetime(),";
	sqlmsg << "datetime()";
	if(ipv4_addr != nullptr)
	{
		sqlmsg << ",'" << ipv4_addr << "'" << ",";
		sqlmsg << "datetime()";
	}
	sqlmsg << ");";
	sqlMessage = sqlmsg.str();

	for(uint8_t r = 0; r < MAX_RETRY_TRANSACTION; ++r)
	{
		if(r != 0)
		{
			sqlite3_free(zErrMsg);
			this_thread::sleep_for(RETRY_TRANSACTION_TIME);
		}
		rc = sqlite3_exec(db, sqlMessage.c_str(), NULL, 0, &zErrMsg);
		if( (rc != SQLITE_BUSY) and (rc != SQLITE_LOCKED) ) break;
	}
	if( (rc != SQLITE_OK) and (rc != SQLITE_CONSTRAINT) )
	{
		edata.message = "SQL error: " + mssg2string(zErrMsg);
		edata.type = SNM_DB_SQL_ERROR;
		ei->onEvent(edata);
	}
	else if(rc == SQLITE_OK)
	{
		infoMessage += string(mac_addr);
		toDBMessageLog(infoMessage);
		edata.message = infoMessage;
		edata.type = SNM_DB_NEW_MAC_ENTRY;
		ei->onEvent(edata);
	}
	sqlite3_free(zErrMsg);
	return rc;
}
//
int dbManager::updARProw(const char *mac_addr, const char *ipv4_addr)
{
	int rc;
	char *zErrMsg = nullptr;
	struct eventData edata = {SNM_DB_MODULE_NAME, "updARProw()", "", SNM_DB_SQL_ERROR};
	stringstream sqlmsg;
	string sqlMessage;

	sqlmsg << "UPDATE ARP SET ";
	sqlmsg << "mac_upd_ts=";
	sqlmsg << "datetime()";
	if(ipv4_addr != nullptr)
	{
		sqlmsg << ", ipv4='";
		sqlmsg << ipv4_addr << "', ";
		sqlmsg << "ipv4_upd_ts=";
		sqlmsg << "datetime()";
	}
	sqlmsg << " WHERE ";
	sqlmsg << "mac='" << mac_addr << "';";
	sqlMessage = sqlmsg.str();

	for(uint8_t r = 0; r < MAX_RETRY_TRANSACTION; ++r)
	{
		if(r != 0)
		{
			sqlite3_free(zErrMsg);
			this_thread::sleep_for(RETRY_TRANSACTION_TIME);
		}
		rc = sqlite3_exec(db, sqlMessage.c_str(), NULL, 0, &zErrMsg);
		if( (rc != SQLITE_BUSY) and (rc != SQLITE_LOCKED) ) break;
	}
	if(rc != SQLITE_OK)
	{
		edata.message = "SQL error: " + mssg2string(zErrMsg);
		ei->onEvent(edata);
		sqlite3_free(zErrMsg);
	}
	return rc;
}
//
int dbManager::toARProw(const char *mac_addr, const char *ipv4_addr)
{
	int rc;

	if( (ipv4_addr != nullptr) and (ipv4_addr[0] == '0') ) ipv4_addr = nullptr; // to avoid "0.0.0.0" ipv4 address
	rc = newARProw(mac_addr, ipv4_addr);
	if(rc == SQLITE_CONSTRAINT)
		return updARProw(mac_addr, ipv4_addr);
	else
		return rc;
}
// DNS
const char *dbManager::getDNSHostName(string mac_addr)
{
	int rc;
	struct eventData edata = {SNM_DB_MODULE_NAME, "getDNSHostName()", "", SNM_DB_SQL_ERROR};
	static __thread char host_name[1025] = {0};
	string sql = "SELECT host_name FROM DNS WHERE mac='" + mac_addr + "';";
	sqlite3_stmt *stmt = nullptr;

	rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0);
	if(rc != SQLITE_OK)
	{
		edata.message = "prepare SQL error: " + mtx_sqlite3_errmsg(db);
		ei->onEvent(edata);
		sqlite3_finalize(stmt);
		return nullptr;
	}
	else
	{
		rc = sqlite3_step(stmt);
		if(rc == SQLITE_ROW)
		{
			strcpy( host_name, (const char *) sqlite3_column_text( stmt, 0 ) );
		}
		else if(rc == SQLITE_DONE) // entry doesn't exist
		{
			sqlite3_finalize(stmt);
			return nullptr;
		}
		else
		{
			edata.message = "step SQL error: " + mtx_sqlite3_errmsg(db);
			ei->onEvent(edata);
			sqlite3_finalize(stmt);
			return nullptr;
		}
	}
	sqlite3_finalize(stmt);
	return (const char *) host_name;
}
//
int dbManager::newDNSrow(string mac_addr, const char * host_name)
{
	int rc;
	char *zErrMsg = nullptr;
	struct eventData edata = {SNM_DB_MODULE_NAME, "newDNSrow()", "", SNM_DB_SQL_ERROR};
	stringstream sqlmsg;
	string sqlMessage;

	sqlmsg << "BEGIN;";
	// Message to 'DNS'
	sqlmsg << " INSERT OR ROLLBACK into DNS";
	sqlmsg << "(mac, host_name, host_upd_ts, host_add_ts)";
	sqlmsg << " VALUES" << "(";
	sqlmsg << "'" << mac_addr << "'" << ",";
	sqlmsg << "'" << host_name << "'" << ",";
	sqlmsg << "datetime(),";
	sqlmsg << "datetime()";
	sqlmsg << ");";
	// Message to 'DNS_JOURNAL'
	sqlmsg << " INSERT into DNS_JOURNAL";
	sqlmsg << "(mac, host_name, prev_name, record_ts)";
	sqlmsg << " VALUES" << "(";
	sqlmsg << "'" << mac_addr << "'" << ",";
	sqlmsg << "'" << host_name << "'" << ",";
	sqlmsg << "'" << "" << "',";
	sqlmsg << "datetime()";
	sqlmsg << ");";
	sqlmsg << " COMMIT;";
	sqlMessage = sqlmsg.str();

	for(uint8_t r = 0; r < MAX_RETRY_TRANSACTION; r++)
	{
		if(r != 0)
		{
			sqlite3_free(zErrMsg);
			sqlite3_exec(db, "ROLLBACK;", NULL, 0, NULL);
			this_thread::sleep_for(RETRY_TRANSACTION_TIME);
		}
		rc = sqlite3_exec(db, sqlMessage.c_str(), NULL, 0, &zErrMsg);
		if( (rc != SQLITE_BUSY) and (rc != SQLITE_LOCKED) ) break;
	}
	if(rc == SQLITE_CONSTRAINT)
	{
		sqlite3_free(zErrMsg);
		return rc;
	}
	if(rc != SQLITE_OK)
	{
		sqlite3_exec( db, "ROLLBACK;", NULL, 0, NULL );
		edata.message = "SQL error: " + mssg2string(zErrMsg);
		ei->onEvent(edata);
		sqlite3_free(zErrMsg);
	}
	return rc;
}
//
int dbManager::updDNSrow(string mac_addr, const char *host_name)
{
	int rc;
	char *zErrMsg = nullptr;
	struct eventData edata = {SNM_DB_MODULE_NAME, "updDNSrow()", "", SNM_DB_SQL_ERROR};
	stringstream sqlmsg;
	string sqlMessage;
	const char *prev_name = getDNSHostName(mac_addr);

	if(prev_name == nullptr) return SQLITE_DONE;

	sqlmsg << "BEGIN;";
	// Message to 'DNS'
	sqlmsg << " UPDATE DNS SET ";
	sqlmsg << "host_name='";
	sqlmsg << host_name << "', ";
	sqlmsg << "host_upd_ts=";
	sqlmsg << "datetime()";
	sqlmsg << " WHERE ";
	sqlmsg << "mac='" << mac_addr << "';";
	if( strcmp(prev_name, host_name) )
	{
		// Message to 'DNS_JOURNAL'
		sqlmsg << " INSERT into DNS_JOURNAL";
		sqlmsg << "(mac, host_name, prev_name, record_ts)";
		sqlmsg << " VALUES" << "(";
		sqlmsg << "'" << mac_addr << "'" << ",";
		sqlmsg << "'" << host_name << "'" << ",";
		sqlmsg << "'" << prev_name << "',";
		sqlmsg << "datetime()";
		sqlmsg << ");";

	}
	sqlmsg << " COMMIT;";
	sqlMessage = sqlmsg.str();

	for(uint8_t r = 0; r < MAX_RETRY_TRANSACTION; r++)
	{
		if(r != 0)
		{
			sqlite3_free(zErrMsg);
			sqlite3_exec(db, "ROLLBACK;", NULL, 0, NULL);
			this_thread::sleep_for(RETRY_TRANSACTION_TIME);
		}
		rc = sqlite3_exec(db, sqlMessage.c_str(), NULL, 0, &zErrMsg);
		if( (rc != SQLITE_BUSY) and (rc != SQLITE_LOCKED) ) break;
	}
	if(rc != SQLITE_OK)
	{
		sqlite3_exec(db, "ROLLBACK;", NULL, 0, NULL);
		edata.message = "SQL error: " + mssg2string(zErrMsg);
		ei->onEvent(edata);
		sqlite3_free(zErrMsg);
	}
	return rc;
}
//
int dbManager::toDNSrow(string mac_addr, const char *host_name)
{
	int rc;

	if( strcmp(host_name, "") == 0 )
	{
		return updDNSrow(mac_addr, host_name);
	}
	else
	{
		rc = newDNSrow(mac_addr, host_name);
	}
	if(rc == SQLITE_CONSTRAINT)
		return updDNSrow(mac_addr, host_name);
	else
		return rc;
}
// NBNS
const char *dbManager::getNBNSHostName(const char *mac_addr)
{
	int rc;
	struct eventData edata = {SNM_DB_MODULE_NAME, "getNBNSHostName()", "", SNM_DB_SQL_ERROR};
	static __thread char host_name[NETBIOS_NAME_LEN] = {0};
	string sql = "SELECT host_name FROM NBNS WHERE mac='" + string( mac_addr ) + "';";
	sqlite3_stmt *stmt = nullptr;

	rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0);
	if(rc != SQLITE_OK)
	{
		edata.message = "prepare SQL error: " + mtx_sqlite3_errmsg(db);
		ei->onEvent(edata);
		sqlite3_finalize(stmt);
		return nullptr;
	}
	else
	{
		rc = sqlite3_step(stmt);
		if(rc != SQLITE_ROW)
		{
			edata.message = "step SQL error: " + mtx_sqlite3_errmsg(db);
			ei->onEvent(edata);
			sqlite3_finalize(stmt);
			return nullptr;
		}
		else
		{
			strcpy( host_name, (const char *) sqlite3_column_text( stmt, 0 ) );
		}
	}
	sqlite3_finalize(stmt);
	return (const char *) host_name;
}
//
int dbManager::newNBNSrow(const char *mac_addr, const char *host_name)
{
	int rc;
	char *zErrMsg = nullptr;
	struct eventData edata = {SNM_DB_MODULE_NAME, "newNBNSrow()", "", SNM_DB_SQL_ERROR};
	stringstream sqlmsg;
	string sqlMessage;

	sqlmsg << "BEGIN;";
	// Message to 'NBNS'
	sqlmsg << " INSERT OR ROLLBACK into NBNS";
	sqlmsg << "(mac, host_name, host_upd_ts, host_add_ts)";
	sqlmsg << " VALUES" << "(";
	sqlmsg << "'" << mac_addr << "'" << ",";
	sqlmsg << "'" << host_name << "'" << ",";
	sqlmsg << "datetime(),";
	sqlmsg << "datetime()";
	sqlmsg << ");";
	// Message to 'NBNS_JOURNAL'
	sqlmsg << " INSERT into NBNS_JOURNAL";
	sqlmsg << "(mac, host_name, prev_name, record_ts)";
	sqlmsg << " VALUES" << "(";
	sqlmsg << "'" << mac_addr << "'" << ",";
	sqlmsg << "'" << host_name << "'" << ",";
	sqlmsg << "'" << "" << "',";
	sqlmsg << "datetime()";
	sqlmsg << ");";
	sqlmsg << " COMMIT;";
	sqlMessage = sqlmsg.str();

	for(uint8_t r = 0; r < MAX_RETRY_TRANSACTION; r++)
	{
		if(r != 0)
		{
			sqlite3_free(zErrMsg);
			sqlite3_exec(db, "ROLLBACK;", NULL, 0, NULL);
			this_thread::sleep_for(RETRY_TRANSACTION_TIME);
		}
		rc = sqlite3_exec(db, sqlMessage.c_str(), NULL, 0, &zErrMsg);
		if( (rc != SQLITE_BUSY) and (rc != SQLITE_LOCKED) ) break;
	}
	if(rc == SQLITE_CONSTRAINT)
	{
		sqlite3_free(zErrMsg);
		return rc;
	}
	if(rc != SQLITE_OK)
	{
		sqlite3_exec(db, "ROLLBACK;", NULL, 0, NULL);
		edata.message = "SQL error: " + mssg2string(zErrMsg);
		ei->onEvent(edata);
		sqlite3_free(zErrMsg);
	}
	return rc;
}
//
int dbManager::updNBNSrow(const char *mac_addr, const char *host_name)
{
	int rc;
	char *zErrMsg = nullptr;
	struct eventData edata = {SNM_DB_MODULE_NAME, "updNBNSrow()", "", SNM_DB_SQL_ERROR};
	stringstream sqlmsg;
	string sqlMessage;
	const char *prev_name = getNBNSHostName(mac_addr);

	if(prev_name == nullptr) return SQLITE_ERROR;

	sqlmsg << "BEGIN;";
	// Message to 'NBNS'
	sqlmsg << " UPDATE NBNS SET ";
	sqlmsg << "host_name='";
	sqlmsg << host_name << "', ";
	sqlmsg << "host_upd_ts=";
	sqlmsg << "datetime()";
	sqlmsg << " WHERE ";
	sqlmsg << "mac='" << mac_addr << "';";
	if( strcmp(prev_name, host_name) )
	{
		// Message to 'NBNS_JOURNAL'
		sqlmsg << " INSERT into NBNS_JOURNAL";
		sqlmsg << "(mac, host_name, prev_name, record_ts)";
		sqlmsg << " VALUES" << "(";
		sqlmsg << "'" << mac_addr << "'" << ",";
		sqlmsg << "'" << host_name << "'" << ",";
		sqlmsg << "'" << prev_name << "',";
		sqlmsg << "datetime()";
		sqlmsg << ");";
	}
	sqlmsg << " COMMIT;";
	sqlMessage = sqlmsg.str();

	for(uint8_t r = 0; r < MAX_RETRY_TRANSACTION; r++)
	{
		if(r != 0)
		{
			sqlite3_free(zErrMsg);
			sqlite3_exec(db, "ROLLBACK;", NULL, 0, NULL);
			this_thread::sleep_for(RETRY_TRANSACTION_TIME);
		}
		rc = sqlite3_exec(db, sqlMessage.c_str(), NULL, 0, &zErrMsg);
		if( (rc != SQLITE_BUSY) and (rc != SQLITE_LOCKED) ) break;
	}
	if(rc != SQLITE_OK)
	{
		sqlite3_exec(db, "ROLLBACK;", NULL, 0, NULL);
		edata.message = "SQL error: " + mssg2string(zErrMsg);
		ei->onEvent(edata);
		sqlite3_free(zErrMsg);
	}
	return rc;
}
//
int dbManager::toNBNSrow(const char *mac_addr, const char *host_name)
{
	int rc;

	rc = newNBNSrow(mac_addr, host_name);
	if(rc == SQLITE_CONSTRAINT)
		return updNBNSrow(mac_addr, host_name);
	else
		return rc;
}
// mDNS
const char *dbManager::getMDNSHostName(const char *mac_addr)
{
	int rc;
	struct eventData edata = {SNM_DB_MODULE_NAME, "getMDNSHostName()", "", SNM_DB_SQL_ERROR};
	static __thread char host_name[NI_MAXHOST] = {0};
	string sql = "SELECT host_name FROM MDNS WHERE mac='" + string( mac_addr ) + "';";
	sqlite3_stmt *stmt = nullptr;

	rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0);
	if(rc != SQLITE_OK)
	{
		edata.message = "prepare SQL error: " + mtx_sqlite3_errmsg(db);
		ei->onEvent(edata);
		sqlite3_finalize(stmt);
		return nullptr;
	}
	else
	{
		rc = sqlite3_step(stmt);
		if(rc != SQLITE_ROW)
		{
			edata.message = "step SQL error: " + mtx_sqlite3_errmsg(db);
			ei->onEvent(edata);
			sqlite3_finalize(stmt);
			return nullptr;
		}
		else
		{
			strcpy( host_name, (const char *) sqlite3_column_text( stmt, 0 ) );
		}
	}
	sqlite3_finalize(stmt);
	return (const char *) host_name;
}
//
int dbManager::newMDNSrow(const char *mac_addr, const char * host_name)
{
	int rc;
	char *zErrMsg = nullptr;
	struct eventData edata = {SNM_DB_MODULE_NAME, "newMDNSrow()", "", SNM_DB_SQL_ERROR};
	stringstream sqlmsg;
	string sqlMessage;

	sqlmsg << "BEGIN;";
	// Message to 'MDNS'
	sqlmsg << " INSERT OR ROLLBACK into MDNS";
	sqlmsg << "(mac, host_name, host_upd_ts, host_add_ts)";
	sqlmsg << " VALUES" << "(";
	sqlmsg << "'" << mac_addr << "'" << ",";
	sqlmsg << "'" << host_name << "'" << ",";
	sqlmsg << "datetime(),";
	sqlmsg << "datetime()";
	sqlmsg << ");";
	// Message to 'MDNS_JOURNAL'
	sqlmsg << " INSERT into MDNS_JOURNAL";
	sqlmsg << "(mac, host_name, prev_name, record_ts)";
	sqlmsg << " VALUES" << "(";
	sqlmsg << "'" << mac_addr << "'" << ",";
	sqlmsg << "'" << host_name << "'" << ",";
	sqlmsg << "'" << "" << "',";
	sqlmsg << "datetime()";
	sqlmsg << ");";
	sqlmsg << " COMMIT;";
	sqlMessage = sqlmsg.str();

	for(uint8_t r = 0; r < MAX_RETRY_TRANSACTION; r++)
	{
		if(r != 0)
		{
			sqlite3_free(zErrMsg);
			sqlite3_exec(db, "ROLLBACK;", NULL, 0, NULL);
			this_thread::sleep_for(RETRY_TRANSACTION_TIME);
		}
		rc = sqlite3_exec(db, sqlMessage.c_str(), NULL, 0, &zErrMsg);
		if( (rc != SQLITE_BUSY) and (rc != SQLITE_LOCKED) ) break;
	}
	if(rc == SQLITE_CONSTRAINT)
	{
		sqlite3_free(zErrMsg);
		return rc;
	}
	if(rc != SQLITE_OK)
	{
		sqlite3_exec(db, "ROLLBACK;", NULL, 0, NULL);
		edata.message = "SQL error: " + mssg2string(zErrMsg);
		ei->onEvent(edata);
		sqlite3_free(zErrMsg);
	}
	return rc;
}
//
int dbManager::updMDNSrow(const char *mac_addr, const char *host_name)
{
	int rc;
	char *zErrMsg = nullptr;
	struct eventData edata = {SNM_DB_MODULE_NAME, "updMDNSrow()", "", SNM_DB_SQL_ERROR};
	stringstream sqlmsg;
	string sqlMessage;
	const char *prev_name = getMDNSHostName(mac_addr);

	if(prev_name == nullptr) return SQLITE_ERROR;

	sqlmsg << "BEGIN;";
	// Message to 'MDNS'
	sqlmsg << " UPDATE MDNS SET ";
	sqlmsg << "host_name='";
	sqlmsg << host_name << "', ";
	sqlmsg << "host_upd_ts=";
	sqlmsg << "datetime()";
	sqlmsg << " WHERE ";
	sqlmsg << "mac='" << mac_addr << "';";
	if( strcmp(prev_name, host_name) )
	{
		// Message to 'MDNS_JOURNAL'
		sqlmsg << " INSERT into MDNS_JOURNAL";
		sqlmsg << "(mac, host_name, prev_name, record_ts)";
		sqlmsg << " VALUES" << "(";
		sqlmsg << "'" << mac_addr << "'" << ",";
		sqlmsg << "'" << host_name << "'" << ",";
		sqlmsg << "'" << prev_name << "',";
		sqlmsg << "datetime()";
		sqlmsg << ");";

	}
	sqlmsg << " COMMIT;";
	sqlMessage = sqlmsg.str();

	for(uint8_t r = 0; r < MAX_RETRY_TRANSACTION; r++)
	{
		if(r != 0)
		{
			sqlite3_free(zErrMsg);
			sqlite3_exec(db, "ROLLBACK;", NULL, 0, NULL);
			this_thread::sleep_for(RETRY_TRANSACTION_TIME);
		}
		rc = sqlite3_exec(db, sqlMessage.c_str(), NULL, 0, &zErrMsg);
		if( (rc != SQLITE_BUSY) and (rc != SQLITE_LOCKED) ) break;
	}
	if(rc != SQLITE_OK)
	{
		sqlite3_exec(db, "ROLLBACK;", NULL, 0, NULL);
		edata.message = "SQL error: " + mssg2string(zErrMsg);
		ei->onEvent(edata);
		sqlite3_free(zErrMsg);
	}
	return rc;
}
//
int dbManager::toMDNSrow(const char *mac_addr, const char *host_name)
{
	int rc;

	rc = newMDNSrow(mac_addr, host_name);

	if(rc == SQLITE_CONSTRAINT)
		return updMDNSrow(mac_addr, host_name);
	else
		return rc;
}
// UPnP
string dbManager::getUPNPurl(string mac_addr)
{
	int rc;
	struct eventData edata = {SNM_DB_MODULE_NAME, "getUPNPurl()", "", SNM_DB_SQL_ERROR};
	string sql = "SELECT url FROM UPNP WHERE mac='" + mac_addr + "';";
	string url;
	sqlite3_stmt *stmt = nullptr;

	rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0);
	if(rc != SQLITE_OK)
	{
		edata.message = "prepare SQL error: " + mtx_sqlite3_errmsg(db);
		ei->onEvent(edata);
	}
	else
	{
		rc = sqlite3_step(stmt);
		switch(rc)
		{
			case SQLITE_ROW:
				url.append( (const char *) sqlite3_column_text(stmt, 0) );
				break;
			case SQLITE_DONE:
				break;
			default:
				edata.message = "step SQL error: " + mtx_sqlite3_errmsg(db);
				ei->onEvent(edata);
		}
	}
	sqlite3_finalize(stmt);
	return url;
}

int dbManager::newUPNProw(string mac_addr, string device_description, string url)
{
	int rc;
	char *zErrMsg = nullptr;
	struct eventData edata = {SNM_DB_MODULE_NAME, "newUPNProw()", "", SNM_DB_SQL_ERROR};
	stringstream sqlmsg;
	string sqlMessage;

	sqlmsg << "BEGIN;";
	// Message to 'UPNP'
	sqlmsg << " INSERT OR ROLLBACK into UPNP";
	sqlmsg << "(mac, device_description, device_upd_ts, device_add_ts, url)";
	sqlmsg << " VALUES" << "(";
	sqlmsg << "'" << mac_addr << "'" << ",";
	sqlmsg << "'" << device_description << "'" << ",";
	sqlmsg << "datetime(),";
	sqlmsg << "datetime(),";
	sqlmsg << "'" << url << "'";
	sqlmsg << ");";
	// Message to 'UPNP_JOURNAL'
	sqlmsg << " INSERT into UPNP_JOURNAL";
	sqlmsg << "(mac, device_description, urn, prev_device_description, prev_urn, record_ts)";
	sqlmsg << " VALUES" << "(";
	sqlmsg << "'" << mac_addr << "'" << ",";
	sqlmsg << "'" << device_description << "'" << ",";
	sqlmsg << "'" << getURN(url) << "'" << ",";
	sqlmsg << "'" << "" << "',";
	sqlmsg << "'" << "" << "',";
	sqlmsg << "datetime()";
	sqlmsg << ");";
	sqlmsg << " COMMIT;";
	sqlMessage = sqlmsg.str();

	for(uint8_t r = 0; r < MAX_RETRY_TRANSACTION; r++)
	{
		if(r != 0)
		{
			sqlite3_free(zErrMsg);
			sqlite3_exec(db, "ROLLBACK;", NULL, 0, NULL);
			this_thread::sleep_for(RETRY_TRANSACTION_TIME);
		}
		rc = sqlite3_exec(db, sqlMessage.c_str(), NULL, 0, &zErrMsg);
		if( (rc != SQLITE_BUSY) and (rc != SQLITE_LOCKED) ) break;
	}
	if(rc == SQLITE_CONSTRAINT)
	{
		sqlite3_free(zErrMsg);
		return rc;
	}
	if(rc != SQLITE_OK)
	{
		sqlite3_exec( db, "ROLLBACK;", NULL, 0, NULL );
		edata.message = "SQL error: " + mssg2string(zErrMsg);
		ei->onEvent(edata);
		sqlite3_free(zErrMsg);
	}
	return rc;
}

pair<string, string> dbManager::getUPNPdata(string mac_addr)
{
	int rc;
	struct eventData edata = {SNM_DB_MODULE_NAME, "getUPNPdata()", "", SNM_DB_SQL_ERROR};
	string device_description, url;
	string sql = "SELECT device_description, url FROM UPNP WHERE mac='" + mac_addr + "';";
	sqlite3_stmt *stmt = nullptr;

	rc = sqlite3_prepare_v2( db, sql.c_str(), -1, &stmt, 0 );
	if(rc != SQLITE_OK)
	{
		edata.message = "prepare SQL error: " + mtx_sqlite3_errmsg(db);
		ei->onEvent(edata);
	}
	else
	{
		rc = sqlite3_step(stmt);
		if(rc != SQLITE_ROW)
		{
			edata.message = "step SQL error: " + mtx_sqlite3_errmsg(db);
			ei->onEvent(edata);
		}
		else
		{
			device_description.append((char *) sqlite3_column_text(stmt, 0) );
			url.append((char *) sqlite3_column_text(stmt, 1) );
		}
	}
	sqlite3_finalize(stmt);
	return make_pair(device_description, url);
}

// updUPNProw long
int dbManager::updUPNProw(string mac_addr, string device_description, string url)
{
	int rc;
	char *zErrMsg = nullptr;
	struct eventData edata = {SNM_DB_MODULE_NAME, "updUPNProw(long)", "", SNM_DB_SQL_ERROR};
	stringstream sqlmsg;
	string sqlMessage;
	auto prev = getUPNPdata(mac_addr);

	if( prev.second.empty() ) return SQLITE_ERROR;

	sqlmsg << "BEGIN;";
	// Message to 'UPNP'
	sqlmsg << " UPDATE UPNP SET ";
	sqlmsg << "device_description='";
	sqlmsg << device_description << "', ";
	sqlmsg << "device_upd_ts=";
	sqlmsg << "datetime(), ";
	sqlmsg << "url='";
	sqlmsg << url << "'";
	sqlmsg << " WHERE ";
	sqlmsg << "mac='" << mac_addr << "';";
	// Message to 'UPNP_JOURNAL'
	sqlmsg << " INSERT into UPNP_JOURNAL";
	sqlmsg << "(mac, device_description, urn, prev_device_description, prev_urn, record_ts)";
	sqlmsg << " VALUES" << "(";
	sqlmsg << "'" << mac_addr << "'" << ",";
	sqlmsg << "'" << device_description << "'" << ",";
	sqlmsg << "'" << getURN(url) << "'" << ",";
	sqlmsg << "'" << prev.first << "',";
	sqlmsg << "'" << getURN(prev.second) << "',";
	sqlmsg << "datetime()";
	sqlmsg << ");";
	sqlmsg << " COMMIT;";
	sqlMessage = sqlmsg.str();

	for(uint8_t r = 0; r < MAX_RETRY_TRANSACTION; r++)
	{
		if(r != 0)
		{
			sqlite3_free(zErrMsg);
			sqlite3_exec(db, "ROLLBACK;", NULL, 0, NULL);
			this_thread::sleep_for(RETRY_TRANSACTION_TIME);
		}
		rc = sqlite3_exec(db, sqlMessage.c_str(), NULL, 0, &zErrMsg);
		if( (rc != SQLITE_BUSY) and (rc != SQLITE_LOCKED) ) break;
	}
	if(rc != SQLITE_OK)
	{
		sqlite3_exec(db, "ROLLBACK;", NULL, 0, NULL);
		edata.message = "SQL error: " + mssg2string(zErrMsg);
		ei->onEvent(edata);
		sqlite3_free(zErrMsg);
	}
	return rc;
}

// updUPNProw short
int dbManager::updUPNProw(string mac_addr, string url)
{
	int rc;
	char *zErrMsg = nullptr;
	struct eventData edata = {SNM_DB_MODULE_NAME, "updUPNProw(short)", "", SNM_DB_SQL_ERROR};
	stringstream sqlmsg;
	string sqlMessage;

	// Message to 'UPNP'
	sqlmsg << "UPDATE UPNP SET ";
	sqlmsg << "url=";
	sqlmsg << "'" << url << "', ";
	sqlmsg << "device_upd_ts=";
	sqlmsg << "datetime()";
	sqlmsg << " WHERE ";
	sqlmsg << "mac='" << mac_addr << "';";
	sqlMessage = sqlmsg.str();

	for(uint8_t r = 0; r < MAX_RETRY_TRANSACTION; r++)
	{
		if(r != 0)
		{
			sqlite3_free(zErrMsg);
			this_thread::sleep_for(RETRY_TRANSACTION_TIME);
		}
		rc = sqlite3_exec(db, sqlMessage.c_str(), NULL, 0, &zErrMsg);
		if( (rc != SQLITE_BUSY) and (rc != SQLITE_LOCKED) ) break;
	}
	if(rc != SQLITE_OK)
	{
		edata.message = "SQL error: " + mssg2string(zErrMsg);
		ei->onEvent(edata);
		sqlite3_free(zErrMsg);
	}
	return rc;
}
// LLDP
string dbManager::getLLDPsysName(string mac_addr)
{
	int rc;
	struct eventData edata = {SNM_DB_MODULE_NAME, "getLLDPsysName()", "", SNM_DB_SQL_ERROR};
	string sys_name;
	string sql = "SELECT system_name FROM LLDP WHERE mac='" + mac_addr + "';";
	sqlite3_stmt *stmt = nullptr;

	rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0);
	if(rc != SQLITE_OK)
	{
		edata.message = "prepare SQL error: " + mtx_sqlite3_errmsg(db);
		ei->onEvent(edata);
		sys_name = "SQLITE_ERROR";
	}
	else
	{
		rc = sqlite3_step(stmt);
		if(rc != SQLITE_ROW)
		{
			edata.message = "step SQL error: " + mtx_sqlite3_errmsg(db);
			ei->onEvent(edata);
			sys_name = "SQLITE_ERROR";
		}
		else
		{
			sys_name.append( (const char *) sqlite3_column_text(stmt, 0) );
		}
	}
	sqlite3_finalize(stmt);
	return sys_name;
}
//
int dbManager::newLLDProw(string mac_addr, string sys_name)
{
	int rc;
	char *zErrMsg = nullptr;
	struct eventData edata = {SNM_DB_MODULE_NAME, "newLLDProw()", "", SNM_DB_SQL_ERROR};
	stringstream sqlmsg;
	string sqlMessage;

	sqlmsg << "BEGIN;";
	// Message to 'LLDP'
	sqlmsg << " INSERT OR ROLLBACK into LLDP";
	sqlmsg << "(mac, system_name, name_upd_ts, name_add_ts)";
	sqlmsg << " VALUES" << "(";
	sqlmsg << "'" << mac_addr << "'" << ",";
	sqlmsg << "'" << sys_name << "'" << ",";
	sqlmsg << "datetime(),";
	sqlmsg << "datetime()";
	sqlmsg << ");";
	// Message to 'NBNS_JOURNAL'
	sqlmsg << " INSERT into LLDP_JOURNAL";
	sqlmsg << "(mac, system_name, prev_name, record_ts)";
	sqlmsg << " VALUES" << "(";
	sqlmsg << "'" << mac_addr << "'" << ",";
	sqlmsg << "'" << sys_name << "'" << ",";
	sqlmsg << "'" << "" << "',";
	sqlmsg << "datetime()";
	sqlmsg << ");";
	sqlmsg << " COMMIT;";
	sqlMessage = sqlmsg.str();

	for(uint8_t r = 0; r < MAX_RETRY_TRANSACTION; r++)
	{
		if(r != 0)
		{
			sqlite3_free(zErrMsg);
			sqlite3_exec(db, "ROLLBACK;", NULL, 0, NULL);
			this_thread::sleep_for(RETRY_TRANSACTION_TIME);
		}
		rc = sqlite3_exec(db, sqlMessage.c_str(), NULL, 0, &zErrMsg);
		if( (rc != SQLITE_BUSY) and (rc != SQLITE_LOCKED) ) break;
	}
	if(rc == SQLITE_CONSTRAINT)
	{
		sqlite3_free(zErrMsg);
		return rc;
	}
	if(rc != SQLITE_OK)
	{
		sqlite3_exec(db, "ROLLBACK;", NULL, 0, NULL);
		edata.message = "SQL error: " + mssg2string(zErrMsg);
		ei->onEvent(edata);
		sqlite3_free(zErrMsg);
	}
	return rc;
}
//
int dbManager::updLLDProw(string mac_addr, string sys_name)
{
	int rc;
	char *zErrMsg = nullptr;
	struct eventData edata = {SNM_DB_MODULE_NAME, "updLLDProw()", "", SNM_DB_SQL_ERROR};
	stringstream sqlmsg;
	string sqlMessage;
	string prev_name = getLLDPsysName(mac_addr);

	if(prev_name == "SQLITE_ERROR") return SQLITE_ERROR;

	sqlmsg << "BEGIN;";
	// Message to 'LLDP'
	sqlmsg << " UPDATE LLDP SET ";
	sqlmsg << "system_name='";
	sqlmsg << sys_name << "', ";
	sqlmsg << "name_upd_ts=";
	sqlmsg << "datetime()";
	sqlmsg << " WHERE ";
	sqlmsg << "mac='" << mac_addr << "';";
	if(prev_name != sys_name)
	{
		// Message to 'LLDP_JOURNAL'
		sqlmsg << " INSERT into LLDP_JOURNAL";
		sqlmsg << "(mac, system_name, prev_name, record_ts)";
		sqlmsg << " VALUES" << "(";
		sqlmsg << "'" << mac_addr << "'" << ",";
		sqlmsg << "'" << sys_name << "'" << ",";
		sqlmsg << "'" << prev_name << "',";
		sqlmsg << "datetime()";
		sqlmsg << ");";

	}
	sqlmsg << " COMMIT;";
	sqlMessage = sqlmsg.str();

	for(uint8_t r = 0; r < MAX_RETRY_TRANSACTION; r++)
	{
		if(r != 0)
		{
			sqlite3_free(zErrMsg);
			sqlite3_exec(db, "ROLLBACK;", NULL, 0, NULL);
			this_thread::sleep_for(RETRY_TRANSACTION_TIME);
		}
		rc = sqlite3_exec(db, sqlMessage.c_str(), NULL, 0, &zErrMsg);
		if( (rc != SQLITE_BUSY) and (rc != SQLITE_LOCKED) ) break;
	}
	if(rc != SQLITE_OK)
	{
		sqlite3_exec(db, "ROLLBACK;", NULL, 0, NULL);
		edata.message = "SQL error: " + mssg2string(zErrMsg);
		ei->onEvent(edata);
		sqlite3_free(zErrMsg);
	}
	return rc;
}
//
int dbManager::toLLDProw(string mac_addr, string sys_name)
{
	int rc;

	rc = newLLDProw(mac_addr, sys_name);
	if(rc == SQLITE_CONSTRAINT)
		return updLLDProw(mac_addr, sys_name);
	else
		return rc;
}
// DHCPv4
string dbManager::getDHCPv4HostName(string mac_addr)
{
	int rc;
	struct eventData edata = {SNM_DB_MODULE_NAME, "getDHCPv4HostName()", "", SNM_DB_SQL_ERROR};
	string host_name;
	string sql = "SELECT host_name FROM DHCPV4 WHERE mac='" + mac_addr + "';";
	sqlite3_stmt *stmt = nullptr;

	rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0);
	if(rc != SQLITE_OK)
	{
		edata.message = "prepare SQL error: " + mtx_sqlite3_errmsg(db);
		ei->onEvent(edata);
		host_name = "SQLITE_ERROR";
	}
	else
	{
		rc = sqlite3_step(stmt);
		if(rc != SQLITE_ROW)
		{
			edata.message = "step SQL error: " + mtx_sqlite3_errmsg(db);
			ei->onEvent(edata);
			host_name = "SQLITE_ERROR";
		}
		else
		{
			host_name.append( (const char *) sqlite3_column_text(stmt, 0) );
		}
	}
	sqlite3_finalize(stmt);
	return host_name;
}
//
int dbManager::newDHCPv4row(string mac_addr, string host_name, string vendor_id, string params, string options)
{
	int rc;
	char *zErrMsg = nullptr;
	struct eventData edata = {SNM_DB_MODULE_NAME, "newDHCPv4row()", "", SNM_DB_SQL_ERROR};
	stringstream sqlmsg;
	string sqlMessage;

	sqlmsg << "BEGIN;";
	// Message to 'DHCPV4'
	sqlmsg << " INSERT OR ROLLBACK into DHCPV4";
	sqlmsg << "(mac, host_name, record_upd_ts, record_add_ts, vendor_identifier, parameters, options)";
	sqlmsg << " VALUES" << "(";
	sqlmsg << "'" << mac_addr  << "',";
	sqlmsg << "'" << host_name << "',";
	sqlmsg << "datetime(),";
	sqlmsg << "datetime(),";
	sqlmsg << "'" << vendor_id << "',";
	sqlmsg << "'" << params    << "',";
	sqlmsg << "'" << options   << "'";
	sqlmsg << ");";
	// Message to 'DHCPV4_JOURNAL'
	sqlmsg << " INSERT into DHCPV4_JOURNAL";
	sqlmsg << "(mac, host_name, prev_name, record_ts)";
	sqlmsg << " VALUES" << "(";
	sqlmsg << "'" << mac_addr  << "',";
	sqlmsg << "'" << host_name << "',";
	sqlmsg << "'" << "" << "',";
	sqlmsg << "datetime()";
	sqlmsg << ");";
	sqlmsg << " COMMIT;";
	sqlMessage = sqlmsg.str();

	for(uint8_t r = 0; r < MAX_RETRY_TRANSACTION; r++)
	{
		if(r != 0)
		{
			sqlite3_free(zErrMsg);
			sqlite3_exec(db, "ROLLBACK;", NULL, 0, NULL);
			this_thread::sleep_for(RETRY_TRANSACTION_TIME);
		}
		rc = sqlite3_exec(db, sqlMessage.c_str(), NULL, 0, &zErrMsg);
		if( (rc != SQLITE_BUSY) and (rc != SQLITE_LOCKED) ) break;
	}
	if(rc == SQLITE_CONSTRAINT)
	{
		sqlite3_free(zErrMsg);
		return rc;
	}
	if(rc != SQLITE_OK)
	{
		sqlite3_exec(db, "ROLLBACK;", NULL, 0, NULL);
		edata.message = "SQL error: " + mssg2string(zErrMsg);
		ei->onEvent(edata);
		sqlite3_free(zErrMsg);
	}
	return rc;
}
//
int dbManager::updDHCPv4row(string mac_addr, string host_name, string vendor_id, string params, string options)
{
	int rc;
	char *zErrMsg = nullptr;
	struct eventData edata = {SNM_DB_MODULE_NAME, "updDHCPv4row()", "", SNM_DB_SQL_ERROR};
	stringstream sqlmsg;
	string sqlMessage;
	string prev_name = getDHCPv4HostName(mac_addr);

	if(prev_name == "SQLITE_ERROR") return SQLITE_ERROR;

	sqlmsg << "BEGIN;";
	// Message to 'DHCPV4'
	sqlmsg << " UPDATE DHCPV4 SET ";
	sqlmsg << "host_name='";
	sqlmsg << host_name << "',";
	sqlmsg << "record_upd_ts=";
	sqlmsg << "datetime(),";
	sqlmsg << "vendor_identifier='";
	sqlmsg <<  vendor_id << "',";
	sqlmsg << "parameters='";
	sqlmsg << params << "',";
	sqlmsg << "options='";
	sqlmsg << options << "'";
	sqlmsg << " WHERE ";
	sqlmsg << "mac='" << mac_addr << "';";
	if(prev_name != host_name)
	{
		// Message to 'DHCPV4_JOURNAL'
		sqlmsg << " INSERT into DHCPV4_JOURNAL";
		sqlmsg << "(mac, host_name, prev_name, record_ts)";
		sqlmsg << " VALUES" << "(";
		sqlmsg << "'" << mac_addr << "'" << ",";
		sqlmsg << "'" << host_name << "'" << ",";
		sqlmsg << "'" << prev_name << "',";
		sqlmsg << "datetime()";
		sqlmsg << ");";

	}
	sqlmsg << " COMMIT;";
	sqlMessage = sqlmsg.str();

	for(uint8_t r = 0; r < MAX_RETRY_TRANSACTION; r++)
	{
		if(r != 0)
		{
			sqlite3_free(zErrMsg);
			sqlite3_exec(db, "ROLLBACK;", NULL, 0, NULL);
			this_thread::sleep_for(RETRY_TRANSACTION_TIME);
		}
		rc = sqlite3_exec(db, sqlMessage.c_str(), NULL, 0, &zErrMsg);
		if( (rc != SQLITE_BUSY) and (rc != SQLITE_LOCKED) ) break;
	}
	if(rc != SQLITE_OK)
	{
		sqlite3_exec(db, "ROLLBACK;", NULL, 0, NULL);
		edata.message = "SQL error: " + mssg2string(zErrMsg);
		ei->onEvent(edata);
		sqlite3_free(zErrMsg);
	}
	return rc;
}
//
int dbManager::toDHCPv4row(string mac_addr, string host_name, string vendor_id, string params, string options)
{
	int rc;

	rc = newDHCPv4row(mac_addr, host_name, vendor_id, params, options);
	if(rc == SQLITE_CONSTRAINT)
		return updDHCPv4row(mac_addr, host_name, vendor_id, params, options);
	else
		return rc;
}
// LLMNR
const char *dbManager::getLLMNRHostName(const char *mac_addr)
{
	int rc;
	struct eventData edata = {SNM_DB_MODULE_NAME, "getLLMNRHostName()", "", SNM_DB_SQL_ERROR};
	static __thread char host_name[NI_MAXHOST] = {0};
	string sql = "SELECT host_name FROM LLMNR WHERE mac='" + string( mac_addr ) + "';";
	sqlite3_stmt *stmt = nullptr;

	rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0);
	if(rc != SQLITE_OK)
	{
		edata.message = "prepare SQL error: " + mtx_sqlite3_errmsg(db);
		ei->onEvent(edata);
		sqlite3_finalize(stmt);
		return nullptr;
	}
	else
	{
		rc = sqlite3_step(stmt);
		if( rc != SQLITE_ROW )
		{
			edata.message = "step SQL error: " + mtx_sqlite3_errmsg(db);
			ei->onEvent(edata);
			sqlite3_finalize(stmt);
			return nullptr;
		}
		else
		{
			strcpy( host_name, (const char *) sqlite3_column_text(stmt, 0) );
		}
	}
	sqlite3_finalize(stmt);
	return (const char *) host_name;
}
//
int dbManager::newLLMNRrow(const char *mac_addr, const char *host_name)
{
	int rc;
	char *zErrMsg = nullptr;
	struct eventData edata = {SNM_DB_MODULE_NAME, "newLLMNRrow()", "", SNM_DB_SQL_ERROR};
	stringstream sqlmsg;
	string sqlMessage;

	sqlmsg << "BEGIN;";
	// Message to 'NBNS'
	sqlmsg << " INSERT OR ROLLBACK into LLMNR";
	sqlmsg << "(mac, host_name, host_upd_ts, host_add_ts)";
	sqlmsg << " VALUES" << "(";
	sqlmsg << "'" << mac_addr << "'" << ",";
	sqlmsg << "'" << host_name << "'" << ",";
	sqlmsg << "datetime(),";
	sqlmsg << "datetime()";
	sqlmsg << ");";
	// Message to 'NBNS_JOURNAL'
	sqlmsg << " INSERT into LLMNR_JOURNAL";
	sqlmsg << "(mac, host_name, prev_name, record_ts)";
	sqlmsg << " VALUES" << "(";
	sqlmsg << "'" << mac_addr << "'" << ",";
	sqlmsg << "'" << host_name << "'" << ",";
	sqlmsg << "'" << "" << "',";
	sqlmsg << "datetime()";
	sqlmsg << ");";
	sqlmsg << " COMMIT;";
	sqlMessage = sqlmsg.str();

	for(uint8_t r = 0; r < MAX_RETRY_TRANSACTION; r++)
	{
		if(r != 0)
		{
			sqlite3_free(zErrMsg);
			sqlite3_exec(db, "ROLLBACK;", NULL, 0, NULL);
			this_thread::sleep_for(RETRY_TRANSACTION_TIME);
		}
		rc = sqlite3_exec(db, sqlMessage.c_str(), NULL, 0, &zErrMsg);
		if( (rc != SQLITE_BUSY) and (rc != SQLITE_LOCKED) ) break;
	}
	if(rc == SQLITE_CONSTRAINT)
	{
		sqlite3_free(zErrMsg);
		return rc;
	}
	if(rc != SQLITE_OK)
	{
		sqlite3_exec(db, "ROLLBACK;", NULL, 0, NULL);
		edata.message = "SQL error: " + mssg2string(zErrMsg);
		ei->onEvent(edata);
		sqlite3_free(zErrMsg);
	}
	return rc;
}
//
int dbManager::updLLMNRrow(const char *mac_addr, const char *host_name)
{
	int rc;
	char *zErrMsg = nullptr;
	struct eventData edata = {SNM_DB_MODULE_NAME, "updLLMNRrow()", "", SNM_DB_SQL_ERROR};
	stringstream sqlmsg;
	string sqlMessage;
	const char *prev_name = getLLMNRHostName(mac_addr);

	if(prev_name == nullptr) return SQLITE_ERROR;

	sqlmsg << "BEGIN;";
	// Message to 'LLMNR'
	sqlmsg << " UPDATE LLMNR SET ";
	sqlmsg << "host_name='";
	sqlmsg << host_name << "', ";
	sqlmsg << "host_upd_ts=";
	sqlmsg << "datetime()";
	sqlmsg << " WHERE ";
	sqlmsg << "mac='" << mac_addr << "';";
	if( strcmp( prev_name, host_name ) )
	{
		// Message to 'LLMNR_JOURNAL'
		sqlmsg << " INSERT into LLMNR_JOURNAL";
		sqlmsg << "(mac, host_name, prev_name, record_ts)";
		sqlmsg << " VALUES" << "(";
		sqlmsg << "'" << mac_addr << "'" << ",";
		sqlmsg << "'" << host_name << "'" << ",";
		sqlmsg << "'" << prev_name << "',";
		sqlmsg << "datetime()";
		sqlmsg << ");";

	}
	sqlmsg << " COMMIT;";
	sqlMessage = sqlmsg.str();

	for(uint8_t r = 0; r < MAX_RETRY_TRANSACTION; r++)
	{
		if(r != 0)
		{
			sqlite3_free(zErrMsg);
			sqlite3_exec(db, "ROLLBACK;", NULL, 0, NULL);
			this_thread::sleep_for(RETRY_TRANSACTION_TIME);
		}
		rc = sqlite3_exec(db, sqlMessage.c_str(), NULL, 0, &zErrMsg);
		if( (rc != SQLITE_BUSY) and (rc != SQLITE_LOCKED) ) break;
	}
	if(rc != SQLITE_OK)
	{
		sqlite3_exec(db, "ROLLBACK;", NULL, 0, NULL);
		edata.message = "SQL error: " + mssg2string(zErrMsg);
		ei->onEvent(edata);
		sqlite3_free(zErrMsg);
	}
	return rc;
}
//
int dbManager::toLLMNRrow(const char *mac_addr, const char *host_name)
{
	int rc;

	rc = newLLMNRrow(mac_addr, host_name);
	if(rc == SQLITE_CONSTRAINT)
		return updLLMNRrow(mac_addr, host_name);
	else
		return rc;
}
// IPv6
int dbManager::newIPV6row(const char *mac_addr, const char *ipv6_addr, unsigned int if_num)
{
	int rc;
	char *zErrMsg = nullptr;
	struct eventData edata = {SNM_DB_MODULE_NAME, "newIPV6row()", "", 0};
	stringstream sqlmsg;
	string sqlMessage;
	//string infoMessage = "New IPv6 address has been detected for MAC: ";
	string infoMessage = "New IPv6 host has been detected: ";

	sqlmsg << "INSERT OR ROLLBACK into IPV6";
	sqlmsg << "(mac, mac_upd_ts, mac_add_ts, ipv6_ll, if_num, ipv6_upd_ts)";
	sqlmsg << " VALUES" << "(";
	sqlmsg << "'" << mac_addr << "'" << ",";
	sqlmsg << "datetime(),";
	sqlmsg << "datetime()";
	sqlmsg << ",'" << ipv6_addr << "'";
	sqlmsg << "," << if_num << ",";
	sqlmsg << "datetime()";
	sqlmsg << ");";
	sqlMessage = sqlmsg.str();

	for(uint8_t r = 0; r < MAX_RETRY_TRANSACTION; ++r)
	{
		if(r != 0)
		{
			sqlite3_free(zErrMsg);
			this_thread::sleep_for(RETRY_TRANSACTION_TIME);
		}
		rc = sqlite3_exec(db, sqlMessage.c_str(), NULL, 0, &zErrMsg);
		if( (rc != SQLITE_BUSY) and (rc != SQLITE_LOCKED) ) break;
	}
	if( (rc != SQLITE_OK) and (rc != SQLITE_CONSTRAINT) )
	{
		edata.message = "SQL error: " + mssg2string(zErrMsg);
		edata.type = SNM_DB_SQL_ERROR;
		ei->onEvent(edata);
	}
	else if(rc == SQLITE_OK)
	{
		infoMessage += string(mac_addr);
		toDBMessageLog(infoMessage);
		edata.message = infoMessage;
		edata.type = SNM_DB_NEW_IPV6_ENTRY;
		ei->onEvent(edata);
	}
	sqlite3_free(zErrMsg);
	return rc;
}
//
int dbManager::updIPV6row(const char *mac_addr, const char *ipv6_addr, unsigned int if_num)
{
	int rc;
	char *zErrMsg = nullptr;
	struct eventData edata = {SNM_DB_MODULE_NAME, "updIPV6row()", "", SNM_DB_SQL_ERROR};
	stringstream sqlmsg;
	string sqlMessage;

	sqlmsg << "UPDATE IPV6 SET ";
	sqlmsg << "mac_upd_ts=";
	sqlmsg << "datetime()";
	sqlmsg << ", ipv6_ll='";
	sqlmsg << ipv6_addr << "'";
	sqlmsg << ", if_num=";
	sqlmsg << if_num << ", ";
	sqlmsg << "ipv6_upd_ts=";
	sqlmsg << "datetime()";
	sqlmsg << " WHERE ";
	sqlmsg << "mac='" << mac_addr << "';";
	sqlMessage = sqlmsg.str();

	for(uint8_t r = 0; r < MAX_RETRY_TRANSACTION; ++r)
	{
		if(r != 0)
		{
			sqlite3_free(zErrMsg);
			this_thread::sleep_for(RETRY_TRANSACTION_TIME);
		}
		rc = sqlite3_exec(db, sqlMessage.c_str(), NULL, 0, &zErrMsg);
		if( (rc != SQLITE_BUSY) and (rc != SQLITE_LOCKED) ) break;
	}
	if(rc != SQLITE_OK)
	{
		edata.message = "SQL error: " + mssg2string(zErrMsg);
		ei->onEvent(edata);
		sqlite3_free(zErrMsg);
	}
	return rc;
}
//
int dbManager::toIPV6row(const char *mac_addr, const char *ipv6_addr, unsigned int if_num)
{
	int rc;

	rc = newIPV6row(mac_addr, ipv6_addr, if_num);
	if(rc == SQLITE_OK) toARProw(mac_addr); // try to save to ARP if a new MAC address was added
	if(rc == SQLITE_CONSTRAINT)
		return updIPV6row(mac_addr, ipv6_addr, if_num);
	else
		return rc;
}
