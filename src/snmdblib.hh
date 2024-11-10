//======================================================================================
// Name        : snmdblib.hh
// Author      : Dmitry Komyagin
// Version     : 1.02
// Created on  : Nov 4, 2024
// Copyright   : Public domain
// Description : Header file for SNMONITOR DBM library, Linux, ISO C++14
//======================================================================================

/*************************************************************************************************
 * THIRD-PARTY SOFTWARE NOTE
 *
 * The following software might be used in this product:
 *
 * SQLite Library, http://www.sqlite.org/
 * Read THIRD-PARTY-LICENSES.txt or visit: https://www.sqlite.org/copyright.html
 *************************************************************************************************/

#ifndef SNMDBLIB_HH_
#define SNMDBLIB_HH_

#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <thread>
#include <unordered_set>
#include <map>
#include <array>
#include <regex>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <string.h>
#include <sqlite3.h>

#include "eventinf.hh"

//
#define MAX_RETRY_TRANSACTION  3
#define RETRY_TRANSACTION_TIME 150ms
//
int uploadMACvendors(sqlite3 *db, const char *csvFileName, bool verbose = false);
//
int initDB(const char *filename, sqlite3 **db);
//
std::string getURN(std::string url);

// Class 'dbManager' definition
class dbManager
{
private:
	sqlite3 *db;
	eventInformer *ei;
private:
	//
	static int callbackIPv4hosts(void *ipv4Hosts, int argc, char **argv, char **azColName);
	//
	static int callbackIPv4MAC(void *macIPv4, int argc, char **argv, char **azColName);
	// DNS
	const char *getDNSHostName(std::string mac_addr);
	// NBNS
	const char *getNBNSHostName(const char *mac_addr);
	// mDNS
	const char *getMDNSHostName(const char *mac_addr);
	// UPnP
	std::pair<std::string, std::string> getUPNPdata(std::string mac_addr);
	// LLDP
	std::string getLLDPsysName(std::string mac_addr);
	// DHCPv4
	std::string getDHCPv4HostName(std::string mac_addr);
	// LLMNR
	const char *getLLMNRHostName(const char *mac_addr);
public:
	//Constructor
	dbManager(sqlite3 *database, eventInformer *eventInf);
	//
	int toDBMessageLog(std::string mssg);
	//
	int getFreshIPv4hosts(std::unordered_set<in_addr_t> *ipv4Hosts);
	int getIPv4hosts(std::unordered_set<in_addr_t> *ipv4Hosts );
	int getFreshIPv4MAC(std::map<std::string, std::string> *macIPv4);
	// ARP
	int newARProw(const char *mac_addr, const char *ipv4_addr=nullptr);
	int updARProw(const char *mac_addr, const char *ipv4_addr=nullptr);
	int toARProw (const char *mac_addr, const char *ipv4_addr=nullptr);
	// DNS
	int newDNSrow(std::string mac_addr, const char * host_name);
	int updDNSrow(std::string mac_addr, const char *host_name);
	int toDNSrow (std::string mac_addr, const char *host_name);
	// NBNS
	int newNBNSrow(const char *mac_addr, const char *host_name);
	int updNBNSrow(const char *mac_addr, const char *host_name);
	int toNBNSrow (const char *mac_addr, const char *host_name);
	// mDNS
	int newMDNSrow(const char *mac_addr, const char * host_name);
	int updMDNSrow(const char *mac_addr, const char *host_name);
	int toMDNSrow (const char *mac_addr, const char *host_name);
	// UPnP
	std::string getUPNPurl(std::string mac_addr);
	int newUPNProw(std::string mac_addr, std::string device_description, std::string url);
	int updUPNProw(std::string mac_addr, std::string device_description, std::string url);
	int updUPNProw(std::string mac_addr, std::string url);
	// LLDP
	int newLLDProw(std::string mac_addr, std::string sys_name);
	int updLLDProw(std::string mac_addr, std::string sys_name);
	int toLLDProw (std::string mac_addr, std::string sys_name);
	// DHCPv4
	int newDHCPv4row(std::string mac_addr, std::string host_name, std::string vendor_id, std::string params, std::string options);
	int updDHCPv4row(std::string mac_addr, std::string host_name, std::string vendor_id, std::string params, std::string options);
	int toDHCPv4row (std::string mac_addr, std::string host_name, std::string vendor_id, std::string params, std::string options);
	// LLMNR
	int newLLMNRrow(const char *mac_addr, const char *host_name);
	int updLLMNRrow(const char *mac_addr, const char *host_name);
	int toLLMNRrow (const char *mac_addr, const char *host_name);
	// IPv6
	int newIPV6row(const char *mac_addr, const char *ipv6_addr, unsigned int if_num);
	int updIPV6row(const char *mac_addr, const char *ipv6_addr, unsigned int if_num);
	int toIPV6row (const char *mac_addr, const char *ipv6_addr, unsigned int if_num);
};

#endif /* SNMDBLIB_HH_ */
