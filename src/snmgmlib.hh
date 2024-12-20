//======================================================================================
// Name        : snmgmlib.hh
// Author      : Dmitry Komyagin
// Version     : 1.1
// Created on  : Dec 12, 2024
// Copyright   : Public domain
// Description : Header file for SNMONITOR General Monitor library, Linux, ISO C++14
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

#ifndef SNMGMLIB_HH_
#define SNMGMLIB_HH_

#include "snmnetlib.hh"
#include "snmdblib.hh"
#include "snmcommlib.hh"
#include "snmeventinf.hh"
#include "eventinf.hh"

#include <random>
#include <sys/ioctl.h>

struct service_record
{
	bool init_err_flag = false;
	std::atomic<bool> run_flag = {true};
	std::mutex mtx;
	std::condition_variable cv;
	std::atomic<uint64_t> rcount  = {0};
	std::atomic<uint64_t> scount  = {0};
	std::atomic<uint64_t> rbcount = {0};
	std::atomic<uint64_t> sbcount = {0};
	std::atomic<uint64_t> sqlerrc = {0};
	std::atomic<uint64_t> interrc = {0};
};

// Class 'arpAnycastHelper' definition
class arpAnycastHelper
{
private:
	std::mutex mtx, mtx_in;
	std::condition_variable cv;
	std::atomic<bool> _rflag = {true}, _iflag = {false}, _oflag = {false};
	std::atomic<bool> init_flag = {false}, exit_flag = {false};
	bool init_err_flag = false;
	struct interface *ifa;
	in_addr_t target_ip_addr = 0;
	unsigned char target_mac_addr[ETH_ALEN];
	bool is_unicast = false;
	bool result = false;
	class eventInformer *ei;
private:
	//
	bool compareMAC(unsigned char *mac1, unsigned char *mac2);
	//
	void arpHelper();
public:
	// Constructor
	arpAnycastHelper(struct interface *ifa_info, eventInformer *eventInf);
	//
	bool checkMAC(unsigned char *mac_addr, in_addr_t ip_addr);
	//
	bool getMAC(in_addr_t ip_addr, unsigned char *mac_addr);
	//
	bool getInitErrStatus() const;
	//
	void stopARPhelper();
	//
	bool getExitStatus() const;
};

// GMonitor

#define ZERO_IF 0
#define ARP_RECEIVER_SRV		 1
#define DHCPV4_RCVR_REQ_SRV		 2
#define DHCPV4_RCVR_RPL_SRV		 3
#define ARP_REQUESTOR_SRV		11
#define DNS_RESOLVER_SRV		12
#define NBNS_RESOLVER_SRV		13
#define MDNS4_RESOLVER_SRV		14
#define UPNP_RESOLVER_SRV		15
#define LLDP_RECEIVER_SRV		16
#define MSBRWS_LISTENER_SRV		18
#define IPV4_MC_LISTENER_SRV	19
#define MDNSV4_DOSVC_SRV        20
#define IPV6_LISTENER_SRV		61
#define MDNS6_RESOLVER_SRV		62

// ARP
#define ARP_REQUESTOR_SLEEP_TIME       300s
// DNS
#define DNS_RESOLVER_SLEEP_TIME        180s
#define DNS_RESOLVER_START_TIME_SHIFT   70s
// NBNS
#define NBNSV4RESOLVER_INIT_TIME_SHIFT  75s
#define NBNSV4RESOLVER_SLEEP_TIME	   300s
// mDNS
#define MDNSV4RESOLVER_INIT_TIME_SHIFT  60s
#define MDNSV4RESOLVER_SLEEP_TIME	   180s
// mDNS dosvc
#define MDNSV4DOSVC_INIT_TIME_SHIFT     55s
#define MDNSV4DOSVC_SLEEP_TIME         180s
// UPnP
#define UPNPV4RESOLVER_INIT_SLEEP_TIME  30s
#define UPNPV4RESOLVER_SLEEP_TIME      180s
// mDNS IPv6
#define MDNSV6RESOLVER_INIT_TIME_SHIFT  10s
#define MDNSV6RESOLVER_SLEEP_TIME	   180s

// Class 'GMonitor' definition
class GMonitor
{
private:
	const std::string startTime = getUTCtime();

	std::atomic<bool> _nl_run_flag  = {true};       // NetLink run flag
	std::atomic<bool> _nl_init_flag = {false};      // NetLink init flag
	std::atomic<bool> _nl_exit_flag = {false};      // NetLink exit flag
	std::atomic<bool> _monitor_init_flag = {false};	// GMonitor init flag
	std::atomic<bool> _monitor_run_flag  = {true};  // GMonitor run flag
	std::atomic<bool> _monitor_exit_flag = {false}; // GMonitor exit flag
	std::condition_variable cv_nl, cv_err;
	std::mutex m_mtx, err_mtx, srvc_mtx, if_mtx, srvc_init_mtx;

	std::map<unsigned int, struct interface> actIf, updIf;
	std::queue<unsigned int> delQueue, newQueue;

	std::map< std::pair<unsigned int, uint8_t>, struct service_record& > services;
	std::map<unsigned int, class arpAnycastHelper*> arpHlpr;
	std::vector<class arpAnycastHelper*> delARPhelper;
	service_record err_srv;
	std::atomic<short> _svcInitCnt;
	std::atomic<short> _svcExitCnt;
	std::atomic<uint8_t> rt_err_cntr = {0};

	class dbManager *dbm;
	class eventInformer *ei;

	bool IPv6_enabled, enable_IPv6_only;

	const std::map<uint8_t, std::string> srvcNames =
	{
		{ARP_RECEIVER_SRV  ,   "ARP receiver"},
		{DNS_RESOLVER_SRV,     "DNS resolver"},
		{DHCPV4_RCVR_REQ_SRV,  "DHCPv4 requests"},
		{DHCPV4_RCVR_RPL_SRV,  "DHCPv4 replies"},
		{ARP_REQUESTOR_SRV,    "ARP requestor"},
		{NBNS_RESOLVER_SRV,    "NBNS resolver"},
		{MDNS4_RESOLVER_SRV,   "mDNSv4 resolver"},
		{UPNP_RESOLVER_SRV,    "UPnP resolver"},
		{LLDP_RECEIVER_SRV,    "LLDP receiver"},
		{MDNSV4_DOSVC_SRV,     "mDNSv4 dosvc"},
		{MSBRWS_LISTENER_SRV,  "MS-BRWS listener"},
		{IPV4_MC_LISTENER_SRV, "IPv4 multicast listener"},
		{IPV6_LISTENER_SRV,    "IPv6 listener"},
		{MDNS6_RESOLVER_SRV,   "mDNSv6 resolver"}
	};
public:
	sqlite3 *mdb;
private:
	// NetLink monitor
	void nlMonitor(uint32_t nl_groups);
	// Stops NetLink monitor
	void stopNLmonitor();
	//
	int getInterfaces(bool ipv6only);
	//
	uint32_t ipv4IfIndex(in_addr_t ipv4);
	//
	void toSrvMap(unsigned int ifIndex, uint8_t srv_type, struct service_record& srv);
	//
	void toSrvMapErr(unsigned int ifIndex, uint8_t srv_type);
	//
	void onReturn(unsigned int ifIndex, uint8_t srv_type);
	//
	void runMonitor();
	//
	void startServices(unsigned int ifIndex, bool db_mssg);
	//
	void stopServices(unsigned int ifIndex);
	//
	int getIfData(struct interface* ifa_info);
	//
	void stopAllServices();
	//
	void arpReceiver(bool verbose);
	//
	void arpRequestor(unsigned int ifIndex, uint8_t srv_type);
	//
	void dnsResolver(unsigned int ifIndex, uint8_t srv_type);
	//
	void nbnsv4Resolver(unsigned int ifIndex, uint8_t srv_type);
	//
	void msbrws4Listener(unsigned int ifIndex, uint8_t srv_type);
	//
	void mdnsv4Resolver(unsigned int ifIndex, uint8_t srv_type);
	//
	void mdnsv4DOSVC(unsigned int ifIndex, uint8_t srv_type);
	//
	upnp_device_info *getUPnPDeviceInfo(struct uri_data *uri, in_addr if_ipv4_addr);
	//
	void upnpv4Resolver(unsigned int ifIndex, uint8_t srv_type);
	//
	void lldpReceiver(unsigned int ifIndex, uint8_t srv_type);
	//
	void dhcpv4ListenerClient(uint8_t srv_type);
	//
	void dhcpv4ListenerServer(uint8_t srv_type);
	//
	void ipv4MCListener(unsigned int ifIndex, uint8_t srv_type);
	//
	void ipv6Listener(unsigned int ifIndex, uint8_t srv_type);
	//
	void mdnsv6Resolver(unsigned int ifIndex, uint8_t srv_type);
	// Output active interfaces information to string
	std::string strAcitivIPv4if();
public:
	// Constructor
	GMonitor(sqlite3 *db, eventInformer *eventInf, bool enable_IPv6);
	// Destructor
	~GMonitor();
	// Output active interfaces information to console
	void coutAcitivIPv4if();
	// Output number of running services to console
	void coutTotalServicesRunning();
	// Get number of running services
	int totalServicesRunning();
	// Returns boolean value that indicates whether GMonitor is stated
	bool isStarted() const;
	// Check initialize errors
	std::tuple<short, short, short> checkInitErrors();
	// Check execution errors
	std::tuple<short, short, short, uint64_t> checkExecErrors();
	// Returns boolean value that indicates whether IPv6 monitoring is enabled
	bool isIPv6enabled() const;
	// Get start time
	std::string getStartTime() const;
	// Output statistics to console
	void coutStatistics();
	// Output GMonitor info to console
	void coutInfo();
	// Get network interface information in HTML format
	std::string htmlInfo(uint8_t *numIf);
	// Get statistics in HTML format
	std::string htmlStatistics(uint8_t *numRows);
};

#endif /* SNMGMLIB_HH_ */
