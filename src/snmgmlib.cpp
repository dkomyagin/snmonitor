//======================================================================================
// Name        : snmgmlib.cpp
// Author      : Dmitry Komyagin
// Version     : 1.0
// Created on  : Nov 8, 2024
// Copyright   : Public domain
// Description : SNMONITOR General Monitor library, Linux, ISO C++14
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

#include "snmgmlib.h"
#include "snmgmlib.hh"

using namespace std;

//
static string err2string(char *err)
{
	if(err)
		return string(err);
	else
		return "no message provided";
}

// NetLink
//
static int get_ifa_info(struct nlmsghdr *nh, int msg_len, bool verbose = false)
{
	struct ifaddrmsg *ifa = (struct ifaddrmsg *) NLMSG_DATA(nh);
	struct rtattr *rta;
	struct ifa_cacheinfo *cinfo;
	struct in_addr if_addr;

	if(verbose) // debug only
	{
		cout << "family: " << (int) ifa->ifa_family << endl; // socket.h AF_*
		cout << "prefix: /" << dec << (int) ifa->ifa_prefixlen << endl;
		cout << "scope: " << dec << (int) ifa->ifa_scope << endl; // rtnetlink.h RT_SCOPE_*
		cout << "interface idx: " << dec << ifa->ifa_index << endl;
		cout << "flags: " << hex << (int) ifa->ifa_flags << endl;
		cout.unsetf(ios::hex);  // restore flags state

		for ( rta = IFA_RTA(ifa); RTA_OK( rta, msg_len ); rta = RTA_NEXT( rta, msg_len ) )
		{
			switch(rta->rta_type)
			{
				case IFA_ADDRESS:
					if_addr.s_addr = (in_addr_t) *((uint32_t *) RTA_DATA(rta));
					cout << "address: " << inet_ntoa(if_addr) << endl;
					break;
				case IFA_LOCAL: // see note in if_addr.h
					if_addr.s_addr = (in_addr_t) *((uint32_t *) RTA_DATA(rta));
					cout << "local address: " << inet_ntoa(if_addr) << endl;
					break;
				case IFA_BROADCAST:
					if_addr.s_addr = (in_addr_t) *((uint32_t *) RTA_DATA(rta));
					cout << "broadcast address: " << inet_ntoa(if_addr) << endl;
					break;
				case IFA_LABEL: // name of the interface
					cout << "interface name: " << ((char *) RTA_DATA(rta)) << endl;
					break;
				case IFA_FLAGS:
					cout << "flags: " << hex << (uint32_t) *((uint32_t *) RTA_DATA(rta)) << endl;
					cout.unsetf(ios::hex);  // restore flags state
					break;
				case IFA_CACHEINFO:
					cinfo = (struct ifa_cacheinfo *) RTA_DATA(rta);
					cout << "Cache info structure" << endl;
					cout << "Valid: " << dec << cinfo->ifa_valid << "s" << endl;
					cout << "Preferred: " << dec << cinfo->ifa_prefered << "s" << endl;
					cout << "CStamp: " << dec << cinfo->cstamp << endl;
					cout << "TStamp: " << dec << cinfo->tstamp << endl;
					break;
				default:
					cout << "attr len "  << dec << rta->rta_len << endl;
					cout << "attr type " << rta->rta_type << endl;
			}
		}
	}
	return ifa->ifa_index;
}

// Class 'arpAnycastHelper' methods
// Constructor
arpAnycastHelper::arpAnycastHelper(struct interface *ifa_info, eventInformer *eventInf)
{
	ifa = ifa_info;
	memset( target_mac_addr, 0,  sizeof(target_mac_addr) );
	ei = eventInf;

	thread arpHelper_thread( &arpAnycastHelper::arpHelper, this );
	arpHelper_thread.detach();
	while(!init_flag) this_thread::yield(); // waiting for thread to be initialized
}
//
bool arpAnycastHelper::checkMAC(unsigned char *mac_addr, in_addr_t ip_addr)
{
	lock_guard<mutex>  lock(mtx_in);
	if(!_rflag) return false;
	unique_lock<mutex> lck(mtx);

	target_ip_addr = ip_addr;
	memcpy(target_mac_addr, mac_addr, ETH_ALEN);
	is_unicast = true;
	 _iflag = true;
	cv.notify_one();
	while(!_oflag) cv.wait(lck);
	_oflag = false;
	if(!_rflag) return false;
	if(result)
	{
		result = false;
		return true;
	}
	else
	{
		result = false;
		return false;
	}
}
//
bool arpAnycastHelper::getMAC(in_addr_t ip_addr, unsigned char *mac_addr)
{
	lock_guard<mutex>  lock(mtx_in);
	if(!_rflag) return false;
	unique_lock<mutex> lck(mtx);

	target_ip_addr = ip_addr;
	is_unicast = false;
	 _iflag = true;
	cv.notify_one();
	while(!_oflag) cv.wait(lck);
	_oflag = false;
	if(!_rflag) return false;
	if(result)
	{
		memcpy(mac_addr, target_mac_addr, ETH_ALEN);
		result = false;
		return true;
	}
	else
	{
		result = false;
		return false;
	}
}
//
bool arpAnycastHelper::getInitErrStatus() const
{
	return init_err_flag;
}
//
void arpAnycastHelper::stopARPhelper()
{
	_rflag = false;
	_iflag = true;
	cv.notify_all();
    while(!exit_flag) this_thread::yield(); // waiting for arpHelper() to be ended
}
//
bool arpAnycastHelper::getExitStatus() const
{
	return exit_flag;
}
//
bool arpAnycastHelper::compareMAC(unsigned char *mac1, unsigned char *mac2)
{
	for(int i=0; i < ETH_ALEN; i++)
		if( mac1[i] != mac2[i] ) return false;
	return true;
}
//
void arpAnycastHelper::arpHelper()
{
	int sd, l;
	struct eventData evdata = {SNM_AAH_MODULE_NAME, "arpHelper()", "", 0};
	struct sockaddr_ll ssa = {0};
	char sbuffer[ARP_BUFFER_SIZE] = {0};
	char rbuffer[ARP_BUFFER_SIZE] = {0};
	struct ethhdr *send_req = (struct ethhdr *) sbuffer;
	struct arphdr_eth_ipv4 *arp_req = (struct arphdr_eth_ipv4 *)(sbuffer + ETH_HLEN);
	struct arphdr_eth_ipv4 *arp_rsp = (struct arphdr_eth_ipv4 *)(rbuffer + ETH_HLEN);

	// Ethernet frame
	send_req->h_proto = HTONS(ETH_P_ARP);  // Setting protocol of the packet to ARP

	// Set source address to sender mac address
	memcpy(send_req->h_source, ifa->mac_addr, ETH_ALEN);

	// ARP packet
	arp_req->ar_hrd = HTONS(ARPHRD_ETHER);
	arp_req->ar_pro = HTONS(ETH_P_IP);
	arp_req->ar_hln = ETH_ALEN;
	arp_req->ar_pln = IPV4_ALENGTH;
	arp_req->ar_op  = HTONS(ARPOP_REQUEST);
	arp_req->ar_sip = ifa->ip_addr.s_addr;

	// Set sender mac address
	memcpy(arp_req->ar_sha, ifa->mac_addr, ETH_ALEN);

	// Prepare link layer data
	ssa.sll_family   = AF_PACKET;
	ssa.sll_protocol = HTONS(ETH_P_ARP);
	ssa.sll_ifindex  = ifa->if_index;
	ssa.sll_hatype   = HTONS(ARPHRD_ETHER);
	ssa.sll_pkttype  = PACKET_BROADCAST;
	ssa.sll_halen    = ETH_ALEN;

	// Assign physical layer address
	memcpy(ssa.sll_addr, ifa->mac_addr, ETH_ALEN);
	sd = socket( AF_PACKET, SOCK_RAW, HTONS(ETH_P_ARP) );

	if (sd == -1)
	{
		evdata.message = "Failed to create socket descriptor: " + err2string( strerror(errno) );
		evdata.type = SNM_AAH_ERROR_SOCKET;
		ei->onEvent(evdata);
	   	init_err_flag = true;
	   	init_flag = true;
	   	return;
	}
	struct timeval tcp_tv = {.tv_sec = ARP_RETRANS_TIME};
	if(setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &tcp_tv, sizeof(tcp_tv)) == -1)
	{
	   	close(sd);
		evdata.message = "Failed to set socket option: " + err2string( strerror(errno) );
		evdata.type = SNM_AAH_ERROR_OPTION;
		ei->onEvent(evdata);
	   	init_err_flag = true;
	   	init_flag = true;
	   	return;
	}

	init_flag = true;
	unique_lock<mutex> lck(mtx);

	while(_rflag)
	{
		while(!_iflag) cv.wait(lck);
		if(!_rflag) break;

		// Get addresses
		arp_req->ar_tip = target_ip_addr;
		if(is_unicast)
		{
			memcpy(send_req->h_dest, target_mac_addr, ETH_ALEN);
		}
		else
		{
			// Set destination mac address to 0xFFFFFFFFFFFF (broadcast)
			memset(send_req->h_dest, 0xFF, ETH_ALEN);
		}

		_iflag = false;	// Clear input flag
		result = false;

		if(target_ip_addr == ifa->ip_addr.s_addr)
		{
			if(is_unicast)
			{
				result = compareMAC(target_mac_addr, ifa->mac_addr);
			}
			else
			{
				memcpy(target_mac_addr, ifa->mac_addr, ETH_ALEN);
				result = true;
			}
		}
		else
		{
			l = sendto( sd, sbuffer, ARP_BUFFER_SIZE, 0, (struct  sockaddr*) &ssa, sizeof(ssa) );
			if(l == -1)
			{
				evdata.message = "Failed to send: " + err2string( strerror(errno) );
				evdata.type = SNM_AAH_ERROR_SEND;
				ei->onEvent(evdata);
			}
			else
			{
				while(l != -1)
				{
					l = recvfrom(sd, rbuffer, ARP_BUFFER_SIZE, 0, NULL, NULL);
					if( (l == STD_ARP_PACKET_SIZE) and ( arp_rsp->ar_op == HTONS(ARPOP_REPLY) )
												   and (target_ip_addr == arp_rsp->ar_sip) )
					{
						if(is_unicast)
						{
							result = compareMAC(target_mac_addr, arp_rsp->ar_sha);
						}
						else
						{
							memcpy(target_mac_addr, arp_rsp->ar_sha, ETH_ALEN);
							result = true;
						}
						break;
					}
				}
			}
		}
		target_ip_addr = 0;
		_oflag = true;
		cv.notify_one();
	}
	close(sd);
	evdata.message = "Service 'arpHelper' stopped on interface " + to_string(ifa->if_index);
	evdata.type = SNM_AAH_STOPPED;
	ei->onEvent(evdata);
	exit_flag = true;
	return;
}

// Class 'GMonitor' methods
// Constructor
GMonitor::GMonitor(sqlite3 *db, eventInformer *eventInf, bool enable_IPv6)
{
	const struct eventData evdata = {SNM_AAH_MODULE_NAME, "GMonitor()", "Monitor started", SNM_GM_STARTED};
	err_srv.init_err_flag = true; // only this flag makes sense
	mdb = db;
	ei = eventInf;
	dbm = new dbManager(db, ei);

	if(enable_IPv6)
		IPv6_enabled = true;
	else
		IPv6_enabled = false;

	enable_IPv6_only = false; // do not change!

	thread runMonitor_thread(&GMonitor::runMonitor, this);
	runMonitor_thread.detach();
	while(_monitor_init_flag != true) this_thread::yield(); // wait for runMonitor() to be started
	if(!_monitor_exit_flag)	ei->onEvent(evdata);
	return;
}
// Destructor
GMonitor::~GMonitor()
{
	stopAllServices();
	delete(dbm);
}
// Output active interfaces information to string
string GMonitor::strAcitivIPv4if()
{
    stringstream ss;
    char ip6_addr_dot[INET6_ADDRSTRLEN];

    if_mtx.lock();
    uint16_t size = actIf.size();
    ss << "Number of active interfaces: " << size;
    if(size != 0)
    {
        ss << endl;
        for(auto it:actIf)
        {
            ss << "Interface index: " << it.first << ", name: " << it.second.if_name << endl;
            ss << "ip = " << inet_ntoa(it.second.ip_addr);
            ss << ", mask = " << inet_ntoa(it.second.net_mask);
            ss << ", subnet = " << inet_ntoa(it.second.net_addr);
            ss << ", MAC = " << macBtoS(it.second.mac_addr) << endl;
            if(IPv6_enabled)
            {
                ss << "ipv6 link-local = ";
                if(it.second.sin6_scope_id != 0)
                {
                    inet_ntop(AF_INET6, &(it.second.sin6_addr), ip6_addr_dot, INET6_ADDRSTRLEN);
                    ss << ip6_addr_dot;
                }
                else
                {
                    ss << "disabled";
                }
            }
        }
    }
    if_mtx.unlock();
    return ss.str();
}
// Output active interfaces information to console
void GMonitor::coutAcitivIPv4if()
{
	cout << strAcitivIPv4if() + "\n";
}
// Output number of running services to console
void GMonitor::coutTotalServicesRunning()
{
	stringstream ss;
	ss << "Total network services running: " << totalServicesRunning() << endl;
	cout << ss.str();
}
// Get number of running services
int GMonitor::totalServicesRunning()
{
	lock_guard<mutex> lck(srvc_mtx);
	return services.size();
}
// Returns boolean value that indicates whether GMonitor is stated
bool GMonitor::isStarted() const
{
	return (_monitor_init_flag and !_monitor_exit_flag );
}
// Check initialize errors
tuple<short, short, short> GMonitor::checkInitErrors()
{
	short e1 = 0, e2 = 0, e3;

	e3 = rt_err_cntr;
	for(auto it:services)
	{
		if(it.second.init_err_flag == true) ++e1;
	}
	for(auto it:arpHlpr)
	{
		if(it.second->getInitErrStatus() == true) ++e2;
	}
	return {e1, e2, e3};
}
// Check execution errors
tuple<short, short, short, uint64_t> GMonitor::checkExecErrors()
{
	short e1 = 0, e2 = 0, e3 = 0;
	uint64_t e4 = 0;

	unique_lock<mutex> lck(err_mtx);
	cv_err.wait(lck);

	if(_monitor_run_flag)
	{
		e3 = rt_err_cntr;
		for(auto it:services)
		{
			if(it.second.init_err_flag == true) ++e1;
			e4 += it.second.sqlerrc;
		}
		for(auto it:arpHlpr)
		{
			if(it.second->getInitErrStatus() == true) ++e2;
		}
	}
	else
	{
		e1 = -1; // Shutdown
	}
	lck.unlock();
	return {e1, e2, e3, e4};
}
// Returns boolean value that indicates whether IPv6 monitoring is enabled
bool GMonitor::isIPv6enabled() const
{
	return IPv6_enabled;
}
// Get start time
string GMonitor::getStartTime() const
{
	return startTime;
}
// Output statistics to console
void GMonitor::coutStatistics()
{
	stringstream ss;
	typedef vector<string> row;
	const row tblHeader = {"Interface", "Service", "Errors", "SQL errors", "Sent packets", "Recvd packets", "Sent broadcasts", "Recvd broadcasts"};
	uint8_t colNum = tblHeader.size();
	row tblRow;
	vector<row> tblArr;
	vector<uint8_t> colSize;

	// Header
	for(string s:tblHeader)
	{
		colSize.push_back( (uint8_t) s.length() );
	}
	tblArr.push_back(tblHeader);
	// Body
	srvc_mtx.lock();
	for(auto it:services)
	{
		tblRow.clear();
		if(it.first.first)
			tblRow.push_back( to_string(it.first.first) );
		else
			tblRow.push_back("all");
		tblRow.push_back( srvcNames.at(it.first.second) );
		tblRow.push_back( to_string(it.second.interrc) );
		tblRow.push_back( to_string(it.second.sqlerrc) );
		tblRow.push_back( to_string(it.second.scount) );
		tblRow.push_back( to_string(it.second.rcount) );
		tblRow.push_back( to_string(it.second.sbcount) );
		tblRow.push_back( to_string(it.second.rbcount) );
		tblArr.push_back(tblRow);
		for(uint8_t i = 0; i < colNum ; ++i)
		{
			colSize[i] = max( (uint8_t) tblRow[i].length(), colSize[i] );
		}
	}
	srvc_mtx.unlock();
	for(auto r:tblArr)
	{
		for(uint8_t i = 0; i < colNum ; ++i)
			ss << setw(colSize[i] + ( i < (colNum -1) ? 2 : 0 ) ) << left << r[i];
		ss << endl;
	}
	ss << "Total network services running: " << (tblArr.size() - 1) << endl;
	cout << ss.str();
}
// Output info to console
void GMonitor::coutInfo()
{
    stringstream ss;

    ss << "Monitoring started at: " << startTime << " UTC" << endl;
    ss << "Total network services running: " << totalServicesRunning() << endl;
    ss << strAcitivIPv4if() << endl;
    cout << ss.str();
}
// Get network interface information in HTML format
string GMonitor::htmlInfo(uint8_t *numIf)
{
	stringstream ss;
	vector<string> tblHeader;
	*numIf = 0;
	char ip6_addr_dot[INET6_ADDRSTRLEN];

	// Table header
	if(IPv6_enabled)
		tblHeader = {"Index", "Name", "IPv4 address", "Mask", "Subnet", "IPv6 link-local",  "MAC address"};
	else
		tblHeader = {"Index", "Name", "IPv4 address", "Mask", "Subnet", "MAC address"};

	ss << "<tr>" << endl;
	for(string col:tblHeader)
	{
		ss << " <th>" << col << "</th>" << endl;
	}
	ss << "</tr>" << endl;

	// Table body
	if_mtx.lock();
	for(auto it:actIf)
	{
		ss << "<tr>" << endl;
		ss << " <td>" << it.first << "</td>" << endl;
		ss << " <td>" << it.second.if_name << "</td>" << endl;
		ss << " <td>" << inet_ntoa(it.second.ip_addr) << "</td>" << endl;
		ss << " <td>" << inet_ntoa(it.second.net_mask) << "</td>" << endl;
		ss << " <td>" << inet_ntoa(it.second.net_addr) << "</td>" << endl;
		if(IPv6_enabled)
		{
			if(it.second.sin6_scope_id != 0)
			{
				inet_ntop(AF_INET6, &(it.second.sin6_addr), ip6_addr_dot, INET6_ADDRSTRLEN);
				ss << " <td>" << ip6_addr_dot << "</td>" << endl;
			}
			else
			{
				ss << " <td>disabled</td>" << endl;
			}
		}
		ss << " <td>" << macBtoS(it.second.mac_addr) << "</td>" << endl;
		ss << "</tr>" << endl;
		++(*numIf);
	}
	if_mtx.unlock();
	return ss.str();
}
// Get statistics in HTML format
string GMonitor::htmlStatistics(uint8_t *numRows)
{
	stringstream ss;
	const vector<string> tblHeader = {"Interface", "Service", "Errors", "SQL errors", "Sent packets", "Recvd packets", "Sent broadcasts", "Recvd broadcasts"};
	*numRows = 0;

	// Table header
	ss << "<tr>" << endl;
	for(string col:tblHeader)
	{
		ss << " <th>" << col << "</th>" << endl;
	}
	ss << "</tr>" << endl;

	// Table body
	srvc_mtx.lock();
	for(auto it:services)
	{
		ss << "<tr>" << endl;
		if(it.first.first)
			ss << " <td>" << it.first.first << "</td>" << endl;
		else
			ss << " <td>any</td>" << endl; // 0 means all interfaces
		ss << " <td>" << srvcNames.at(it.first.second) << "</td>" << endl;
		ss << " <td>" << it.second.interrc << "</td>" << endl;
		ss << " <td>" << it.second.sqlerrc << "</td>" << endl;
		ss << " <td>" << it.second.scount << "</td>" << endl;
		ss << " <td>" << it.second.rcount << "</td>" << endl;
		ss << " <td>" << it.second.sbcount << "</td>" << endl;
		ss << " <td>" << it.second.rbcount << "</td>" << endl;
		ss << "</tr>" << endl;
		++(*numRows);
	}
	srvc_mtx.unlock();
	return ss.str();
}
//
void GMonitor::toSrvMap(unsigned int ifIndex, uint8_t srv_type, struct service_record& srv)
{
	lock_guard<mutex> lck(srvc_mtx);
	services.insert( make_pair( make_pair(ifIndex, srv_type), ref(srv) ) ); // add to services
	_svcInitCnt--;
	return;
}
//
void GMonitor::toSrvMapErr(unsigned int ifIndex, uint8_t srv_type)
{
	toSrvMap( ifIndex, srv_type, ref(err_srv) );
	return;
}
//
void GMonitor::onReturn(unsigned int ifIndex, uint8_t srv_type)
{
	string mssg;
	struct eventData evdata = {SNM_GM_MODULE_NAME, "onReturn()", "", SNM_GM_SRVC_STOPPED};

	_svcExitCnt--;
	mssg = "Service '" + srvcNames.at(srv_type) + "' stopped";
	if(ifIndex) mssg += " on interface "  + to_string(ifIndex);
	evdata.message = mssg;
	ei->onEvent(evdata);

	return;
}
// NetLink monitor
void GMonitor::nlMonitor(uint32_t nl_groups)
{
	struct eventData evdata = {SNM_GM_MODULE_NAME, "nlMonitor()", "", 0};
	int sd, l;
	char buf[4096]; // system page size
	struct sockaddr_nl sa = {0};
	struct iovec iov = { buf, sizeof(buf) };
	struct msghdr msg;
	struct nlmsghdr *nh;
	unsigned int if_idx;

	sd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if(sd == -1)
	{
		evdata.message = "Failed to create socket descriptor: " + err2string( strerror(errno) );
		evdata.type = SNM_GM_ERROR_SOCKET;
		ei->onEvent(evdata);
	  	_nl_exit_flag = true;
	  	_nl_init_flag = true;
	   	return;
	}
	else
	{
	    sa.nl_family = AF_NETLINK;
	    sa.nl_groups = nl_groups;
	    if(bind( sd, (struct sockaddr*) &sa, sizeof(sa) ) == -1)
	    {
	        close(sd);
	        evdata.message = "Failed to bind: " + err2string( strerror(errno) );
	        evdata.type = SNM_GM_ERROR_BIND;
	        ei->onEvent(evdata);
	        _nl_exit_flag = true;
	        _nl_init_flag = true;
	        return;
	    }
	    else
	    {
	        struct timeval tv = {.tv_sec = 3};
	        if(setsockopt( sd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv) ) == -1)
	        {
	            close(sd);
	            evdata.message = "Failed to set timeout option: " + err2string( strerror(errno) );
	            evdata.type = SNM_GM_ERROR_TO_OPTION;
	            ei->onEvent(evdata);
	            _nl_exit_flag = true;
	            _nl_init_flag = true;
	            return;
	        }
	    }
	}
	_nl_init_flag = true;

	msg = { &sa, sizeof(sa), &iov, 1, NULL, 0, 0 };

	while(_nl_run_flag)
	{
		memset( buf, 0, sizeof(buf) );
		if( ( l = recvmsg(sd, &msg, 0) ) <= 0 ) continue;
		if(!_nl_run_flag) break;
		m_mtx.lock();
		for( nh = (struct nlmsghdr *) buf; NLMSG_OK(nh, l); nh = NLMSG_NEXT(nh, l) )
		{
			if(nh->nlmsg_type == NLMSG_DONE) // End of multipart message
			{
				break;
			}
			if(nh->nlmsg_type == NLMSG_ERROR)
			{
				evdata.message = "NLMSG_ERROR";
				evdata.type = SNM_GM_NLMSG_ERROR;
				ei->onEvent(evdata);
				continue;
			}
			switch(nh->nlmsg_type)
			{
				case RTM_NEWADDR:
					if_idx = get_ifa_info(nh, l);
					if(_nl_run_flag) newQueue.push(if_idx);
					break;
				case RTM_DELADDR:
					if_idx = get_ifa_info(nh, l);
					if(_nl_run_flag) delQueue.push(if_idx);
					break;
				case RTM_NEWROUTE:
					break;
				case RTM_DELROUTE:
					break;
				default:
				    break;
			}
		}
		if(_nl_run_flag)
		{
			m_mtx.unlock();
			cv_nl.notify_one();
		}
	}
	close(sd);
	evdata.message = "Service 'NetLink monitor' stopped";
	evdata.type = SNM_GM_NL_STOPPED;
	ei->onEvent(evdata);
	_nl_exit_flag = true;
	return;
}
// Stops NetLink monitor
void GMonitor::stopNLmonitor()
{
    _nl_run_flag = false;
    while(!_nl_exit_flag) this_thread::sleep_for(10ms); // waiting for NL monitor exit
}
//
void GMonitor::runMonitor()
{
	map<unsigned int, struct interface>::iterator aifIt, uifIt;
	unsigned int ifIdx;
	short e1, e2, e3;
	char ip6_addr_dot[INET6_ADDRSTRLEN];
	struct eventData evdata = {SNM_GM_MODULE_NAME, "runMonitor()", "", 0};

	thread nlMonitor_thread(&GMonitor::nlMonitor, this, RTMGRP_IPV4_IFADDR);
	nlMonitor_thread.detach();
	while(_nl_init_flag != true) this_thread::yield(); // waiting for start nlMonitor()
	//
	if(_nl_exit_flag)
	{
		evdata.message = "NetLink monitor init error";
		evdata.type = SNM_GM_INIT_ERROR;
		ei->onEvent(evdata);
		_monitor_exit_flag = true;
		_monitor_init_flag = true; // init finished
		return;
	}
	//
	if(getInterfaces(enable_IPv6_only) != -1)
	{
		actIf = updIf;
	}
	else
	{
		evdata.message = "Interface init error";
		evdata.type = SNM_GM_INIT_ERROR;
		ei->onEvent(evdata);
		stopNLmonitor();
		_monitor_exit_flag = true;
		_monitor_init_flag = true; // init finished
		return;
	}
	//
	_svcInitCnt = 1;
	thread arpReceiver_thread(&GMonitor::arpReceiver, this, false); // true for verbose
	arpReceiver_thread.detach();
	while(_svcInitCnt != 0) this_thread::yield(); // waiting for start arpReceiver()
	if(services.at( make_pair(ZERO_IF, ARP_RECEIVER_SRV) ).init_err_flag) // if arpReceiver() failed to initialize then exit
	{
		evdata.message = "ARP init error";
		evdata.type = SNM_GM_INIT_ERROR;
		ei->onEvent(evdata);
		services.clear();
		stopNLmonitor();
		_monitor_exit_flag = true;
		_monitor_init_flag = true; // init finished
		return;
	}

	// end of basic init cycle

    evdata.message = strAcitivIPv4if();
    evdata.type = SNM_GM_ACTIVE_IFS;
    ei->onEvent(evdata);

	// start multi-interface services
	_svcInitCnt = 1;
	thread dhcpv4ListenerClient_thread(&GMonitor::dhcpv4ListenerClient, this, DHCPV4_RCVR_REQ_SRV);
	dhcpv4ListenerClient_thread.detach();
	_svcInitCnt++;
	thread dhcpv4ListenerServer_thread(&GMonitor::dhcpv4ListenerServer, this, DHCPV4_RCVR_RPL_SRV);
	dhcpv4ListenerServer_thread.detach();

	while(_svcInitCnt != 0) this_thread::yield(); // waiting for start multi-interface services

	// start services
	for(auto it: actIf)
		startServices(it.first, false); // don't save to db log

	tie(e1, e2, e3) = checkInitErrors();
	if( (e1 != 0) or (e2 != 0) ) // exit on init errors
	{
		evdata.message = "Init services error";
		evdata.type = SNM_GM_INIT_ERROR;
		ei->onEvent(evdata);
		stopNLmonitor();
		_monitor_exit_flag = true;
		_monitor_init_flag = true; // init finished
		return;
	}
	// end of init cycle

	_monitor_init_flag = true; // init finished

	unique_lock<mutex> m_lock(m_mtx);

	while(_monitor_run_flag)
	{
		// Garbage collector
		for(auto it = delARPhelper.begin(); it != delARPhelper.end();)
		{
			if( (*it)->getExitStatus() )
			{
				delete(*it);
				it = delARPhelper.erase(it);
			}
			else
				++it;
		}
		while( !delQueue.empty() )
		{
			ifIdx = delQueue.front();
			aifIt = actIf.find(ifIdx);
			if( aifIt != actIf.end() )
			{
				stopServices(ifIdx); // stop services
				if_mtx.lock();
				actIf.erase(aifIt);
				if_mtx.unlock();
			}
			delQueue.pop(); // delete element from queue
		}
		while( !newQueue.empty() )
		{
			ifIdx = newQueue.front();
			aifIt = actIf.find(ifIdx);
			if(getInterfaces(enable_IPv6_only) == -1)
			{
				++rt_err_cntr; // run-time error
				break;
			}
			uifIt = updIf.find(ifIdx);
			if( uifIt != updIf.end() )
			{
				if( aifIt != actIf.end() )
				{
					// check interface
					if(memcmp( &aifIt->second, &uifIt->second, sizeof(struct interface) ) != 0)
					{
						stopServices(ifIdx); // stop services
						if_mtx.lock();
						actIf.erase(aifIt);
						if_mtx.unlock();
					}
				}
				else
				{
					// add interface
					if_mtx.lock();
					actIf.insert(*uifIt); // add new interface to active interfaces before start services!
					if_mtx.unlock();
					err_mtx.lock();
					startServices(ifIdx, true); // save to db log
					err_mtx.unlock();
				}
			}
			else if( aifIt != actIf.end() )
			{
				// delete interface
				stopServices(ifIdx); // stop services
				if_mtx.lock();
				actIf.erase(aifIt);
				if_mtx.unlock();
			}
			newQueue.pop(); // delete element from queue
		}

		for(auto it:actIf)
		{
			if(dbm->toARProw( macBtoS(it.second.mac_addr).c_str(), inet_ntoa(it.second.ip_addr) ) != SQLITE_OK)
			{
				evdata.message = "SQL problem";
				evdata.type = SNM_GM_ERROR_SQL;
				ei->onEvent(evdata);
			}
			if( IPv6_enabled and (it.second.sin6_scope_id != 0) )
			{
				inet_ntop( AF_INET6, &(it.second.sin6_addr), ip6_addr_dot, sizeof(ip6_addr_dot) );
				if(dbm->toIPV6row(macBtoS(it.second.mac_addr).c_str(), ip6_addr_dot, it.second.if_index) != SQLITE_OK)
				{
					evdata.message = "SQL problem";
					evdata.type = SNM_GM_ERROR_SQL;
					ei->onEvent(evdata);
				}
			}
		}
		cv_err.notify_one(); // notify checkErrors function
		if(_monitor_run_flag)
			cv_nl.wait_for(m_lock, 30s);
		else
			break;
	}
	stopNLmonitor();
	ei->setVerbosityLvl(1); // show 'service stopped' messages
	evdata.message = "Monitor stopped";
	evdata.type = SNM_GM_STOPPED;
	ei->onEvent(evdata);
	_monitor_exit_flag = true;
	return;
}
//
void GMonitor::startServices(unsigned int ifIndex, bool db_mssg)
{
	// start services
	srvc_init_mtx.lock();

	arpAnycastHelper *arpARqstr = new arpAnycastHelper(&actIf[ifIndex], ei);
	arpHlpr.insert( make_pair(ifIndex, arpARqstr) );

	_svcInitCnt = 1;
	thread arpRequestor_thread(&GMonitor::arpRequestor, this, ifIndex, ARP_REQUESTOR_SRV);
	arpRequestor_thread.detach();

	_svcInitCnt++;
	thread dnsResolver_thread(&GMonitor::dnsResolver, this, ifIndex, DNS_RESOLVER_SRV);
	dnsResolver_thread.detach();

	_svcInitCnt++;
	thread nbnsv4Resolver_thread(&GMonitor::nbnsv4Resolver, this, ifIndex, NBNS_RESOLVER_SRV);
	nbnsv4Resolver_thread.detach();

	_svcInitCnt++;
	thread mdnsv4Resolver_thread(&GMonitor::mdnsv4Resolver, this, ifIndex, MDNS4_RESOLVER_SRV);
	mdnsv4Resolver_thread.detach();

	_svcInitCnt++;
	thread upnpv4Resolver_thread(&GMonitor::upnpv4Resolver, this, ifIndex, UPNP_RESOLVER_SRV);
	upnpv4Resolver_thread.detach();

	_svcInitCnt++;
	thread lldpReceiver_thread(&GMonitor::lldpReceiver, this, ifIndex, LLDP_RECEIVER_SRV);
	lldpReceiver_thread.detach();

	_svcInitCnt++;
	thread msbrws4Listener_thread(&GMonitor::msbrws4Listener, this, ifIndex, MSBRWS_LISTENER_SRV);
	msbrws4Listener_thread.detach();

	_svcInitCnt++;
	thread ipv4MCListener_thread(&GMonitor::ipv4MCListener, this, ifIndex, IPV4_MC_LISTENER_SRV);
	ipv4MCListener_thread.detach();

	if( IPv6_enabled and (actIf[ifIndex].sin6_scope_id != 0) )
	{
		_svcInitCnt++;
		thread ipv6Listener_thread(&GMonitor::ipv6Listener, this, ifIndex, IPV6_LISTENER_SRV);
		ipv6Listener_thread.detach();

		_svcInitCnt++;
		thread mdnsv6Resolver_thread(&GMonitor::mdnsv6Resolver, this, ifIndex, MDNS6_RESOLVER_SRV);
		mdnsv6Resolver_thread.detach();
	}

	while(_svcInitCnt != 0) this_thread::yield(); // to be sure all services have been started before possible deleting
	srvc_init_mtx.unlock();

	string infoMssg = "Interface " + to_string(ifIndex) + " is up, services started";
	if(db_mssg) dbm->toDBMessageLog(infoMssg);
	struct eventData evdata = {SNM_GM_MODULE_NAME, "startServices()", infoMssg, SNM_GM_IF_UP};
	ei->onEvent(evdata);
	return;
}

void GMonitor::stopServices(unsigned int ifIndex)
{
	// stop services for an interface
	lock_guard<mutex> lck(srvc_init_mtx);
	lock_guard<mutex> lock(srvc_mtx);

	class arpAnycastHelper *arpARqstr = arpHlpr.at(ifIndex);

	for(auto srv=services.begin(); srv!=services.end();)
	{
		if(srv->first.first == ifIndex)
		{
			_svcExitCnt++;
			srv->second.run_flag = false;
			srv->second.cv.notify_one();
			srv = services.erase(srv);
		}
		else
			++srv;
	}

	arpARqstr->stopARPhelper();
	delARPhelper.push_back(arpARqstr);
	arpHlpr.erase(ifIndex);

	string infoMssg = "Interface " + to_string(ifIndex) + " went down, services stopped";
	dbm->toDBMessageLog(infoMssg);
	struct eventData evdata = {SNM_GM_MODULE_NAME, "stopServices()", infoMssg, SNM_GM_IF_DOWN};
	ei->onEvent(evdata);

	return;
}
//
void GMonitor::stopAllServices()
{
	// stop all services
	lock_guard<mutex> lck(srvc_init_mtx);
	lock_guard<mutex> lock(srvc_mtx);

	struct eventData evdata = {SNM_GM_MODULE_NAME, "stopAllServices()", "", 0};
	bool exited;

	_monitor_run_flag = false; // stop monitor
	cv_nl.notify_one();
	cv_err.notify_one();

	while(!_monitor_exit_flag) this_thread::sleep_for(10ms);

	_svcExitCnt = services.size();
	evdata.message = "Services to stop: " + to_string(_svcExitCnt);
	evdata.type = SNM_GM_TO_DOWN;
	ei->onEvent(evdata);

	for(auto srv:services)
	{
		srv.second.run_flag = false;
		if(srv.second.init_err_flag == true)
		{
		    _svcExitCnt--; // already exited
		}
		else
		{
		    srv.second.cv.notify_one();
		}
	}

	while(_svcExitCnt != 0) this_thread::sleep_for(10ms); // to be sure that all services are stopped
	services.clear();

	for(auto it:arpHlpr) it.second->stopARPhelper(); // stop arpHelpers

	// waiting for stopping
	do
	{
		this_thread::sleep_for(10ms);
		exited = true;
		for(auto it:arpHlpr) exited &= it.second->getExitStatus();
	} while(!exited);

	for(auto it:arpHlpr) delete it.second;

    // Garbage collector
    for(auto it = delARPhelper.begin(); it != delARPhelper.end();)
    {
        if( (*it)->getExitStatus() )
        {
            delete(*it);
            it = delARPhelper.erase(it);
        }
        else
            ++it;
    }

	evdata.message = "All network services are stopped";
	evdata.type = SNM_GM_ALL_DOWN;
	ei->onEvent(evdata);
	return;
}
//
int GMonitor::getIfData(struct interface* ifa_info)  // fills in index, mac, mtu fields
{
	struct ifreq ifr = {0};
	int sd;
	struct eventData evdata = {SNM_GM_MODULE_NAME, "getIfData()", "", 0};

	sd = socket(AF_INET, SOCK_STREAM, 0);
	if(sd == -1)
	{
		evdata.message = "Failed to create socket descriptor: " + err2string( strerror(errno) );
		evdata.type = SNM_GM_ERROR_SOCKET;
	  	ei->onEvent(evdata);
	   	return -1;
	}
	strcpy(ifr.ifr_name, ifa_info->if_name);
	if( ioctl(sd, SIOCGIFINDEX, &ifr) == -1 )
	{
		evdata.message = "Failed to get info from ioctl: " + err2string( strerror(errno) );
		evdata.type = SNM_GM_ERROR_IOCTL;
	  	ei->onEvent(evdata);
		close(sd);
		return -1;
	}
	ifa_info->if_index = ifr.ifr_ifindex;

	memset( &ifr, 0, sizeof(struct ifreq) );
	strcpy( ifr.ifr_name, ifa_info->if_name );
	if( ioctl(sd, SIOCGIFHWADDR, &ifr) == -1 )
	{
		evdata.message = "Failed to get info from ioctl: " + err2string( strerror(errno) );
		evdata.type = SNM_GM_ERROR_IOCTL;
	  	ei->onEvent(evdata);
		close(sd);
		return -1;
	}
	memcpy( ifa_info->mac_addr, ifr.ifr_hwaddr.sa_data, sizeof(ifa_info->mac_addr) );

	memset( &ifr, 0, sizeof(struct ifreq) );
	strcpy( ifr.ifr_name, ifa_info->if_name );
	if( ioctl(sd, SIOCGIFMTU, &ifr) == -1 )
	{
		evdata.message = "Failed to get info from ioctl: " + err2string( strerror(errno) );
		evdata.type = SNM_GM_ERROR_IOCTL;
	  	ei->onEvent(evdata);
		close(sd);
		return -1;
	}
	ifa_info->mtu = ifr.ifr_mtu;

	close(sd);
	return 0;
}
//
int GMonitor::getInterfaces(bool ipv6only) // 'ipv6only' enables usage of pure IPv6 interfaces
{
	map<string, struct interface> tmp_if;
	uint32_t scope_id;
	struct ifaddrs* ptr_ifaddrs = nullptr;
	struct eventData evdata = {SNM_GM_MODULE_NAME, "getInterfaces", "", 0};

	auto result = getifaddrs(&ptr_ifaddrs);
	if( result != 0 )
	{
		evdata.message = "getifaddrs(): " + err2string( strerror(errno) );
		evdata.type = SNM_GM_ERROR_GETIFADDRS;
	  	ei->onEvent(evdata);
		return -1;
	}

	for( auto ptr_entry = ptr_ifaddrs; ptr_entry != nullptr; ptr_entry = ptr_entry->ifa_next )
	{
		// non-loopback AF_INET or AF_INET6 interfaces only
		if( ( ( ptr_entry->ifa_addr->sa_family != AF_INET ) and
			  ( ptr_entry->ifa_addr->sa_family != AF_INET6 ) )or
			( (ptr_entry->ifa_flags & IFF_LOOPBACK) != 0 ) ) continue;
		// Sanity check: IFF_UP, IFF_BROADCAST, IFF_RUNNING, IFF_MULTICAST flags MUST be set
		if( (ptr_entry->ifa_flags & 0x1043) != 0x1043 ) continue;

		string if_name = string(ptr_entry->ifa_name);
		if( tmp_if.find(if_name) == tmp_if.end() )
		{
			struct interface ifa_info = {0};
			tmp_if.insert( {if_name, ifa_info} );
			strcpy( tmp_if[if_name].if_name , ptr_entry->ifa_name );
			if( getIfData( &tmp_if[if_name] ) == -1 ) // errors detected
			{
				tmp_if[if_name].if_index = 0; // data error
			}
		}

		if(ptr_entry->ifa_addr->sa_family == AF_INET)
		{
			if(tmp_if[if_name].net_addr.s_addr == 0)
			{
			    if(ptr_entry->ifa_addr != 0)
			    	tmp_if[if_name].ip_addr = ( (struct sockaddr_in*) (ptr_entry->ifa_addr) )->sin_addr;
			    else
			    	tmp_if[if_name].if_index = 0; // data error
			    if(ptr_entry->ifa_netmask != 0)
			    	tmp_if[if_name].net_mask = ((struct sockaddr_in*) ptr_entry->ifa_netmask)->sin_addr;
			    else
			    	tmp_if[if_name].if_index = 0; // data error
			    if(ptr_entry->ifa_broadaddr != 0)
			    	tmp_if[if_name].broadcast_addr = ((struct sockaddr_in*) ptr_entry->ifa_broadaddr)->sin_addr;
			    else
			    	tmp_if[if_name].if_index = 0; // data error

			    tmp_if[if_name].net_addr.s_addr = tmp_if[if_name].ip_addr.s_addr & tmp_if[if_name].net_mask.s_addr;
			    tmp_if[if_name].min_host = ntohl(tmp_if[if_name].net_addr.s_addr) + 1;
			    tmp_if[if_name].max_host = ntohl(tmp_if[if_name].net_addr.s_addr) + ~ntohl(tmp_if[if_name].net_mask.s_addr) - 1;
			}
		}

		if(ptr_entry->ifa_addr->sa_family == AF_INET6)
		{
			scope_id = ((struct sockaddr_in6* ) ptr_entry->ifa_addr)->sin6_scope_id;
			if( scope_id != 0 )
			{
				tmp_if[if_name].sin6_scope_id = scope_id;
				memcpy( &tmp_if[if_name].sin6_addr.__in6_u.__u6_addr8,
						&( ((struct sockaddr_in6* ) ptr_entry->ifa_addr)->sin6_addr.__in6_u.__u6_addr8 ), 16);
			}
		}
    }
	freeifaddrs(ptr_ifaddrs);

    // Save to map
	updIf.clear();

	for(auto it:tmp_if)
	{
		if(it.second.if_index != 0)
		{
			if( !ipv6only and (it.second.ip_addr.s_addr == 0) ) break;
			updIf.insert( {it.second.if_index, it.second} );
		}
	}
	// debug only
	/*
	char buffer[INET6_ADDRSTRLEN];
	for( auto it:updIf )
	{
		cout << "Interface: " << it.second.if_index << ", name: " << it.second.if_name << endl;
		cout << "MAC: " << macBtoS( it.second.mac_addr ) << "  MTU: " << it.second.mtu << endl;
		inet_ntop( AF_INET, &(it.second.ip_addr.s_addr), buffer, INET6_ADDRSTRLEN );
		cout << "IPv4 address: " << buffer << endl;
		inet_ntop( AF_INET, &(it.second.net_mask.s_addr), buffer, INET6_ADDRSTRLEN );
		cout << "Mask: " << buffer << endl;
		inet_ntop( AF_INET, &(it.second.net_addr.s_addr), buffer, INET6_ADDRSTRLEN );
		cout << "Network:   " << buffer << endl;
		uint32_t host = htonl(it.second.min_host);
		inet_ntop( AF_INET, &host, buffer, INET6_ADDRSTRLEN );
		cout << "Min host:  " << buffer << endl;
		host = htonl(it.second.max_host);
		inet_ntop( AF_INET, &host, buffer, INET6_ADDRSTRLEN );
		cout << "Max host:  " << buffer << endl;
		inet_ntop( AF_INET, &(it.second.broadcast_addr.s_addr), buffer, INET6_ADDRSTRLEN );
		cout << "Broadcast: " << buffer << endl;
		inet_ntop( AF_INET6, &(it.second.sin6_addr), buffer, INET6_ADDRSTRLEN );
		cout << "IPv6 link-local: " << buffer << " scope_id=" << it.second.sin6_scope_id << endl;

		cout << endl;
	}
	*/
	return updIf.size();
}
//
uint32_t GMonitor::ipv4IfIndex(in_addr_t ipv4)
{
	uint32_t idx = 0;
	for(auto it:actIf)
	{
		if( (ipv4 & it.second.net_mask.s_addr) == it.second.net_addr.s_addr )
		{
			idx = it.first;
			break;
		}
	}
	return idx;
}
// ARP receiver for all interfaces
void GMonitor::arpReceiver(bool verbose)
{
	struct service_record srv;
	int sd, l;
	char rbuffer[ARP_BUFFER_SIZE] = {0};
	static const unsigned char zero_hw_addr[6] = {};
	struct arphdr_eth_ipv4 *arp_rsp = (struct arphdr_eth_ipv4 *)(rbuffer + ETH_HLEN);
	in_addr rcvd_ip_addr;
	char ip_addr_dot[INET_ADDRSTRLEN] = {0};
	struct eventData evdata = {SNM_GM_MODULE_NAME, "arpReceiver", "", 0};

	sd = socket( AF_PACKET, SOCK_RAW, HTONS(ETH_P_ARP) );
	if(sd == -1)
	{
	   	toSrvMapErr(ZERO_IF, ARP_RECEIVER_SRV); // add to services
		evdata.message = "Failed to create socket descriptor: " + err2string( strerror(errno) );
		evdata.type = SNM_GM_ERROR_SOCKET;
	  	ei->onEvent(evdata);
	   	return;
	}
	// Set timeout for protocol
	struct timeval tv = {.tv_sec = 3};
	if(setsockopt( sd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv) ) == -1)
	{
	   	close(sd);
	   	toSrvMapErr(ZERO_IF, ARP_RECEIVER_SRV); // add to services
		evdata.message = "Failed to set socket option: " + err2string( strerror(errno) );
		evdata.type = SNM_GM_ERROR_OPTION;
	  	ei->onEvent(evdata);
		return;
	}
	else
		toSrvMap( ZERO_IF, ARP_RECEIVER_SRV, ref(srv) ); // add to services

	while(srv.run_flag)
	{
		l = recvfrom(sd, rbuffer, ARP_BUFFER_SIZE, 0, NULL, NULL);
		if(!srv.run_flag) break;
		if(verbose) cout << getLocalTime() << " Received: " << l << " ";
		if(l == STD_ARP_PACKET_SIZE)
		{
			srv.rcount++;
			rcvd_ip_addr.s_addr = arp_rsp->ar_sip;
			inet_ntop(AF_INET, &rcvd_ip_addr, ip_addr_dot, INET_ADDRSTRLEN);
			if(verbose) cout << macBtoS(arp_rsp->ar_sha) << " " << ip_addr_dot;
			if( memcmp(arp_rsp->ar_sha, zero_hw_addr, ETH_ALEN) )
			{
			    if( srv.run_flag and (dbm->toARProw(macBtoS(arp_rsp->ar_sha).c_str(), ip_addr_dot) != SQLITE_OK) ) srv.sqlerrc++;
			}
		}
		if(verbose) cout << endl;
	}
	close(sd);
	onReturn(ZERO_IF, ARP_RECEIVER_SRV);
	return;
}
// ARP requester for an interface
void GMonitor::arpRequestor(unsigned int ifIndex, uint8_t srv_type)
{
	struct service_record srv;
	int sd, l, i = 0;
	unsigned seed;
	struct sockaddr_ll ssa = {0};
	char sbuffer[ARP_BUFFER_SIZE] = {0};
	struct ethhdr *send_req = (struct ethhdr *) sbuffer;
	struct arphdr_eth_ipv4 *arp_req = (struct arphdr_eth_ipv4 *)(sbuffer + ETH_HLEN);
	in_addr_t target_ip_addr;
	vector<in_addr_t> hosts;
	unsigned char maxcount = 5, pcount = 0;
	struct eventData evdata = {SNM_GM_MODULE_NAME, "arpRequestor", "", 0};
	unique_lock<mutex> ulck(srv.mtx);

	struct interface ifa_info = actIf[ifIndex]; // get interface info

	// Ethernet frame
	send_req->h_proto = HTONS(ETH_P_ARP);  // Setting protocol to ARP

	// Set destination mac address to 0xFFFFFFFFFFFF (broadcast)
	memset( send_req->h_dest, 0xFF, sizeof(send_req->h_dest) );
	// Set source mac address
	memcpy( send_req->h_source, ifa_info.mac_addr, sizeof(send_req->h_source) );

	// ARP packet
	arp_req->ar_hrd = HTONS(ARPHRD_ETHER);
	arp_req->ar_pro = HTONS(ETH_P_IP);
	arp_req->ar_hln = ETH_ALEN;
	arp_req->ar_pln = IPV4_ALENGTH;
	arp_req->ar_op  = HTONS(ARPOP_REQUEST);
	arp_req->ar_sip = ifa_info.ip_addr.s_addr;

	// Set sender mac address
	memcpy( arp_req->ar_sha, ifa_info.mac_addr, sizeof(arp_req->ar_sha) );

	// Prepare link layer data
	ssa.sll_family   = AF_PACKET;
	ssa.sll_protocol = HTONS(ETH_P_ARP);
	ssa.sll_ifindex  = ifa_info.if_index;
	ssa.sll_hatype   = HTONS(ARPHRD_ETHER);
	ssa.sll_pkttype  = PACKET_BROADCAST;
	ssa.sll_halen    = ETH_ALEN;

	// Assign physical layer address
	memcpy( ssa.sll_addr, ifa_info.mac_addr, sizeof(ssa.sll_addr) );

	sd = socket( AF_PACKET, SOCK_RAW, HTONS(ETH_P_ARP) );
	if(sd == -1)
	{
		toSrvMapErr(ifIndex, srv_type); // add to services
		evdata.message = "Failed to create socket descriptor: " + err2string( strerror(errno) );
		evdata.type = SNM_GM_ERROR_SOCKET;
	  	ei->onEvent(evdata);
	   	return;
	}
	else
		toSrvMap( ifIndex, srv_type, ref(srv) ); // add to services

	// Prepare vector of the subnet ip addresses
	do
	{
		target_ip_addr = htonl(ifa_info.min_host + i++);
		if(target_ip_addr != ifa_info.ip_addr.s_addr) hosts.push_back(target_ip_addr); // exclude own host
	} while( target_ip_addr != htonl(ifa_info.max_host) );
	if(hosts.size() > 16381) maxcount = 10; // for segments with large number of addresses

	// Send requests
	while(srv.run_flag)
	{
		// Shuffle hosts
	    seed = std::chrono::system_clock::now().time_since_epoch().count();
	    shuffle( hosts.begin(), hosts.end(), default_random_engine(seed) );

		for(auto it_h:hosts)
		{
			arp_req->ar_tip = it_h; //set sender ip
			// Prevent ARP request flooding
			if(pcount >= maxcount)
			{
				this_thread::sleep_for(1s);
				pcount = 0;
			}
			if(srv.run_flag)
				l = sendto( sd, sbuffer, ARP_BUFFER_SIZE, 0, (struct  sockaddr*) &ssa, sizeof(struct sockaddr_ll) );
			else
				break;
			if(l == -1)
			{
				evdata.message = "Failed to send: " + err2string( strerror(errno) );
				evdata.type = SNM_GM_ERROR_SEND;
			  	ei->onEvent(evdata);
				continue;
			}
			else
			{
				srv.scount++;
				pcount++;
			}
		}
		if(srv.run_flag)
		{
			srv.cv.wait_for(ulck, ARP_REQUESTOR_SLEEP_TIME);
			pcount = 0;
		}
		else
			break;
	}
	close(sd);
	onReturn(ifIndex, srv_type);
	return;
}
// DNS resolver
void GMonitor::dnsResolver(unsigned int ifIndex, uint8_t srv_type)
{
	struct service_record srv;
	int rc;
	unordered_set<in_addr_t> hosts;
	struct sockaddr_in sa = {0};
	char hbuf[NI_MAXHOST];
	unsigned char node_mac_addr[ETH_ALEN];

	struct interface ifa_info = actIf[ifIndex]; // get interface info
	toSrvMap( ifIndex, srv_type, ref(srv) ); // add to services
	class arpAnycastHelper* arpAHelper = arpHlpr.at(ifIndex); // pointer to arpAnycastHelper

	unique_lock<mutex> ulck(srv.mtx);
	if(srv.run_flag) srv.cv.wait_for(ulck, DNS_RESOLVER_START_TIME_SHIFT);  // Waiting for ARP resolver

	while(srv.run_flag)
	{
		rc = dbm->getIPv4hosts(&hosts); // get all IPv4 nodes
		if(rc == SQLITE_OK)
		{
			for(auto it: hosts)
			{
				if(ipv4IfIndex(it) != ifa_info.if_index) continue; // host not in this interface
				sa.sin_addr.s_addr = it;
				if(srv.run_flag)
				{
					if( arpAHelper->getMAC(sa.sin_addr.s_addr, node_mac_addr) )
					{
						++srv.scount;
						if( srv.run_flag and (dbm->toARProw( macBtoS(node_mac_addr).c_str(), inet_ntoa(sa.sin_addr) ) != SQLITE_OK) ) ++srv.sqlerrc;
						if(srv.run_flag)
						{
							rc = getDNSv4HostNameFC(it, hbuf);

							//cout << "DNS rc = " << rc << endl;
							//cout << "IP: " << inet_ntoa( sa.sin_addr ) << ", name: " << hbuf;
							//cout << ", MAC: " << macBtoS(node_mac_addr) << endl;

							if( (rc == 0) or (rc == EAI_NONAME)  or (rc == EAI_SELF) )
							{
								++srv.rcount;
								if(srv.run_flag)
								{
									rc = dbm->toDNSrow(macBtoS(node_mac_addr), hbuf);
									if( (rc != SQLITE_OK) and (rc != SQLITE_DONE) ) ++srv.sqlerrc;
								}
							}
							else
							{
								++srv.interrc;
							}
						}
						else break;
					}
				}
				else break;
			}
		}
		else
		{
			srv.sqlerrc++;
		}
		hosts.clear(); // clear hosts vector
		if(srv.run_flag)
			srv.cv.wait_for(ulck, DNS_RESOLVER_SLEEP_TIME);
		else
			break;
	}
	onReturn(ifIndex, srv_type);
	return;
}
// NBNS resolver
void GMonitor::nbnsv4Resolver(unsigned int ifIndex, uint8_t srv_type)
{
	struct service_record srv;
	struct unicast_nbns_name_query_req name_query;
	name_query.header.name_trn_id = htons( getpid() );

	int sd, l, offset, rc;
	unsigned char buffer[1064]; // Maximum size NetBIOS datagram is 1064 bytes
	struct std_nbns_name_staus_rpl *response = (struct std_nbns_name_staus_rpl *) buffer;
	union nbns_packet_flags pckt_response_flags;
	nbns_node_name_entry *node_name;
	char host_name[NETBIOS_NAME_LEN];
	char name_type;
	map<string, string> hosts;
	bool _gflag;
	struct eventData evdata = {SNM_GM_MODULE_NAME, "nbnsv4Resolver", "", 0};

	struct interface ifa_info = actIf[ifIndex]; // get interface info
	class arpAnycastHelper* arpAHelper = arpHlpr.at(ifIndex); // pointer to arpAnycastHelper

	struct sockaddr_in ssa = {0};
	struct sockaddr_in dsa = {0};
	struct sockaddr_in psa;
	socklen_t psa_len;
	dsa.sin_family = AF_INET;
	dsa.sin_port = HTONS(NAME_SERVICE_UDP_PORT);

	ssa.sin_family = AF_INET;
	ssa.sin_port = PORT_ANY;
	ssa.sin_addr = ifa_info.ip_addr;

	sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(sd == -1)
	{
		toSrvMapErr(ifIndex, srv_type); // add to services
		evdata.message = "Failed to create socket descriptor: " + err2string( strerror(errno) );
		evdata.type = SNM_GM_ERROR_SOCKET;
	  	ei->onEvent(evdata);
	   	return;
	}
	else
	{
		struct timeval tv = {.tv_sec = UCAST_REQ_RETRY_TIMEOUT};
		if(setsockopt( sd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv) ) == -1)
		{
			close(sd);
			toSrvMapErr(ifIndex, srv_type); // add to services
			evdata.message = "Failed to set timeout option: " + err2string( strerror(errno) );
			evdata.type = SNM_GM_ERROR_TO_OPTION;
		  	ei->onEvent(evdata);
			return;
		}
		else
		{
			// Bind to interface
			if(bind( sd, (struct sockaddr*) &ssa, sizeof(struct sockaddr_in) ) == -1)
			{
				close(sd);
				toSrvMapErr(ifIndex, srv_type); // add to services
				evdata.message = "Failed to bind: " + err2string( strerror(errno) );
				evdata.type = SNM_GM_ERROR_BIND;
			  	ei->onEvent(evdata);
				return;
			}
			else
			{
				toSrvMap( ifIndex, srv_type, ref(srv) ); // add to services
			}
		}
	}

	unique_lock<mutex> ulck(srv.mtx);
	if(srv.run_flag) srv.cv.wait_for(ulck, NBNSV4RESOLVER_INIT_TIME_SHIFT);  // Waiting for ARP resolver

	while(srv.run_flag)
	{
		rc = dbm->getFreshIPv4MAC(&hosts);
		if(rc == SQLITE_OK)
		{
			for(auto it: hosts)
			{
				dsa.sin_addr.s_addr = inet_addr( it.second.c_str() );
				if( ipv4IfIndex(dsa.sin_addr.s_addr) != ifIndex ) continue; // destination host on different interface
				if(srv.run_flag)
				{
					l = sendto( sd, (char *) &name_query, sizeof(name_query), 0,
								(struct sockaddr *) &dsa, sizeof(struct sockaddr_in) );
					srv.scount++;
				}
				else break;
				if(l == -1)
				{
					evdata.message = "Failed to send: " + err2string( strerror(errno) );
					evdata.type = SNM_GM_ERROR_SEND;
				  	ei->onEvent(evdata);
					continue;
				}
				//cout << "Bytes sent: " << l << " to: " << inet_ntoa(dsa.sin_addr);
				//cout << " idx: " << ipv4IfIndex(dsa.sin_addr.s_addr) << endl;
				_gflag = false;
				while( (l > 0) and !_gflag and srv.run_flag )
				{
					memset( &psa, 0, sizeof(struct sockaddr_in) );
					psa_len = sizeof(struct sockaddr_in);
					l = recvfrom(sd, buffer, sizeof(buffer), 0, (struct sockaddr*) &psa, &psa_len);
					if(!srv.run_flag) break;
					//cout << "Bytes rcvd: " << l << " from: " << inet_ntoa(psa.sin_addr) << endl;
					if( (l > 0) and (psa.sin_addr.s_addr == dsa.sin_addr.s_addr) )
					{
						srv.rcount++;
						pckt_response_flags.flags = ntohs(response->header.flags);
						if( (response->header.name_trn_id == name_query.header.name_trn_id) and
							((pckt_response_flags.bitset.opcode & OPCODE_RESPONSE_FLAG) > 0) and
							(pckt_response_flags.bitset.rcode == 0) )
						{
							//cout << "Response OK" << endl;
							_gflag = true;	// got proper response
							offset = sizeof(struct std_nbns_name_staus_rpl);
							for(int i = 0; i < response->num_names; i++)
							{
								node_name = (nbns_node_name_entry *) &buffer[offset];
								name_type = decode_node_name(node_name->node_name, host_name);
								if( !(ntohs(node_name->name_flags) & GROUP_NAME_FLAG) ) // Not a group name
								{
									if(name_type == 0x00) // Workstation/Redirector
									{
										//cout << host_name << " " << it.first << " " <<  it.second;
										//cout << " idx: " << ipv4IfIndex(dsa.sin_addr.s_addr) << endl;
										if( srv.run_flag and arpAHelper->checkMAC(macStoB(it.first.c_str()), dsa.sin_addr.s_addr) )
										{
											if( srv.run_flag and (dbm->toNBNSrow(it.first.c_str(), host_name) != SQLITE_OK) ) srv.sqlerrc++;
										}
										break;
									}
								}
								offset += sizeof(struct nbns_node_name_entry);
							} // end for
						}
					}
				}
			}
		}
		else
		{
			srv.sqlerrc++;
		}
		if( srv.run_flag )
			srv.cv.wait_for(ulck, NBNSV4RESOLVER_SLEEP_TIME);
		else
			break;
	}
	close(sd);
	onReturn(ifIndex, srv_type);
	return;
}
// MS-BRWS listener
void GMonitor::msbrws4Listener(unsigned int ifIndex, uint8_t srv_type)
{
	struct service_record srv;
	int sd, l;
	unsigned short offset;
	struct sockaddr_in ssa = {0};
	struct sockaddr_in psa;
	socklen_t psa_len;
	unsigned char node_mac_addr[ETH_ALEN];
	struct eventData evdata = {SNM_GM_MODULE_NAME, "msbrws4Listener", "", 0};

	struct interface ifa_info = actIf[ifIndex]; // get interface info
	class arpAnycastHelper* arpAHelper = arpHlpr.at(ifIndex); // pointer to arpAnycastHelper

	unsigned char buffer[ifa_info.mtu];

	struct nbdgm_header *dgm_header = (nbdgm_header *) buffer;
	struct smb_header *smb_hdr;
	struct smb_mailslot_header *mailslot_hdr;
	const char MailSlotBrowse[] = "\\MAILSLOT\\BROWSE";
	struct annt_browser_frame *bf;

    ssa.sin_family = AF_INET;
    ssa.sin_port = HTONS(138);
    ssa.sin_addr = ifa_info.broadcast_addr;

    string source_name, dest_name;
    uint8_t s_name_type, s_name_len, d_name_type, d_name_len;

    sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
   	if(sd == -1)
   	{
   		toSrvMapErr(ifIndex, srv_type); // add to services
		evdata.message = "Failed to create socket descriptor: " + err2string( strerror(errno) );
		evdata.type = SNM_GM_ERROR_SOCKET;
	  	ei->onEvent(evdata);
   	   	return;
   	}
   	else
   	{
   		// Set reuse option for reserved port
		int enbl_flag = 1;
		if(setsockopt( sd, SOL_SOCKET, SO_REUSEADDR, &enbl_flag, sizeof(int) ) == -1)
		{
   			close(sd);
   			toSrvMapErr(ifIndex, srv_type); // add to services
			evdata.message = "Failed to set socket option: " + err2string( strerror(errno) );
			evdata.type = SNM_GM_ERROR_OPTION;
		  	ei->onEvent(evdata);
   			return;
   		}
		else
		{
			// Set timeout for protocol
			struct timeval tv = {.tv_sec = UCAST_REQ_RETRY_TIMEOUT};
			if(setsockopt( sd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv) ) == -1)
			{
	   			close(sd);
	   			toSrvMapErr(ifIndex, srv_type); // add to services
				evdata.message = "Failed to set timeout option: " + err2string( strerror(errno) );
				evdata.type = SNM_GM_ERROR_TO_OPTION;
			  	ei->onEvent(evdata);
	   			return;
			}
			else
			{
				// Bind to broadcast address
				if(bind( sd, (struct sockaddr*) &ssa, sizeof(struct sockaddr_in) ) == -1)
				{
					close(sd);
					toSrvMapErr(ifIndex, srv_type); // add to services
					evdata.message = "Failed to bind to broadcast address: " + err2string( strerror(errno) );
					evdata.type = SNM_GM_ERROR_BIND_BCA;
				  	ei->onEvent(evdata);
					return;
				}
				else
				{
					toSrvMap( ifIndex, srv_type, ref(srv) ); // add to services
				}
			}
		}
   	}

   	while(srv.run_flag)
   	{
   		memset( buffer, 0, sizeof(buffer) );
   		memset( &psa, 0, sizeof(psa) );	psa_len = sizeof(struct sockaddr_in);
   		l = recvfrom(sd, buffer, sizeof(buffer), 0, (struct sockaddr*) &psa, &psa_len);
   		if(l > 0)
   		{
   			++srv.rbcount;
   			if(dgm_header->msg_type != NBDGM_TYPE_DIRECT_GROUP_DGM) continue;
   			offset = sizeof(struct nbdgm_header);
   			tie(source_name, s_name_type, s_name_len) = decode_nbns_name_16( (char *) &buffer[offset] );
   			offset += s_name_len + 2; // add leading length octet and terminating zero octet
   			if(offset > l) continue; // packet size mismatch
   			tie(dest_name, d_name_type, d_name_len) = decode_nbns_name_16( (char *) &buffer[offset] );
   			//cout << "Source name: " << source_name << ", " << nb_name_type.at(s_name_type) << endl;
   			//cout << "Destination name: " << dest_name << ", " << nb_name_type.at(d_name_type) << endl;
   			offset += d_name_len + 2; // add leading length and terminating zero
   			if(offset > l) continue; // packet size mismatch
   			smb_hdr = (struct smb_header *) &buffer[offset];
   			if( (smb_hdr->err_code != 0) or (smb_hdr->command != 0x25) ) continue; // errors
   			offset += sizeof(struct smb_header);
   			if(offset > l) continue; // packet size mismatch
   			mailslot_hdr = (struct smb_mailslot_header *) &buffer[offset];
   			if(strcasecmp( (char*) mailslot_hdr->Words.MailslotName, MailSlotBrowse ) != 0) continue; // errors
   			offset += sizeof(struct smb_mailslot_header) + sizeof(MailSlotBrowse); // size of header + size of mailslot name
   			if( offset > l) continue; // packet size mismatch
   			bf = (struct annt_browser_frame *) &buffer[offset];
   			if(bf->Command == 0x01) // Host Announcement
   			{
   				//cout << "Host Announcement" << endl;
   				//cout << "Host name: " << bf->ServerName << endl;
   				if(string( (char *) bf->ServerName ) == source_name)
   				{
   					++srv.rcount;
   					if( srv.run_flag and arpAHelper->getMAC(psa.sin_addr.s_addr, node_mac_addr) )
	    			{
	    				if(dbm->toNBNSrow(macBtoS(node_mac_addr).c_str(), (char *) bf->ServerName) != SQLITE_OK) srv.sqlerrc++;
	    			}
   				}
   				else
   				{
   					++srv.interrc; // names must be the same
   				}
   			}
   			else if( (bf->Command == 0x0F) and ( (bf->ServerType & SV_TYPE_MASTER_BROWSER) == SV_TYPE_MASTER_BROWSER ) )
   			// Local Master Announcement from acting Master Browser (not election)
   			{
   				//cout << "Local Master Announcement" << endl;
   				//cout << "Host name: " << bf->ServerName << endl;
   				if(string( (char *) bf->ServerName ) == source_name)
   				{
   					++srv.rcount;
   					if( srv.run_flag and arpAHelper->getMAC(psa.sin_addr.s_addr, node_mac_addr) )
	    			{
	    				if(dbm->toNBNSrow(macBtoS(node_mac_addr).c_str(), (char *) bf->ServerName) != SQLITE_OK) srv.sqlerrc++;
	    			}
   				}
   				else
   				{
   					++srv.interrc; // names must be the same
   				}
   			}
   		}
   		else
   		{
   			continue;
   		}
   	} // end while
	close(sd);
	onReturn(ifIndex, srv_type);
	return;
}
//
void GMonitor::mdnsv4Resolver(unsigned int ifIndex, uint8_t srv_type)
{
	struct service_record srv;
	int sd, l;
	unsigned short offset;
	struct sockaddr_in ssa = {0};
	struct sockaddr_in dsa = {0};
	struct sockaddr_in psa = {0};
	socklen_t psa_len;
	vector <in_addr> mdns_nodes_ipv4;
	string domain_name, node_name;
	struct dns_packet_header *mdns_hdr;
	struct dns_rr_tail *rr_tail;
	unsigned char node_mac_addr[ETH_ALEN];
	struct eventData evdata = {SNM_GM_MODULE_NAME, "mdnsv4Resolver", "", 0};

	struct interface ifa_info = actIf[ifIndex]; // get interface info
	class arpAnycastHelper* arpAHelper = arpHlpr.at(ifIndex); // pointer to arpAnycastHelper

	char buffer[ifa_info.mtu];

	string srv_name = "_services._dns-sd._udp.local";
    size_t mdns_s_buf_size; // = sizeof(dns_packet_header) + (srv_name.size() + 2) + sizeof(dns_query_tail);
    char mdns_s_buffer[NI_MAXHOST]; // ??? not sure

    dsa.sin_family = AF_INET;
    dsa.sin_port = HTONS(MDNS_PORT);

    ssa.sin_family = AF_INET;
    ssa.sin_port = PORT_ANY;
    ssa.sin_addr = ifa_info.ip_addr;

    sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
   	if(sd == -1)
   	{
   		toSrvMapErr(ifIndex, srv_type); // add to services
		evdata.message = "Failed to create socket descriptor: " + err2string( strerror(errno) );
		evdata.type = SNM_GM_ERROR_SOCKET;
	  	ei->onEvent(evdata);
   	   	return;
   	}
   	else
   	{
   		// Set timeout for protocol
   		struct timeval tv = {.tv_sec = UCAST_REQ_RETRY_TIMEOUT};
   		if(setsockopt( sd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv) ) == -1)
   		{
   			close(sd);
   			toSrvMapErr(ifIndex, srv_type); // add to services
			evdata.message = "Failed to set timeout option: " + err2string( strerror(errno) );
			evdata.type = SNM_GM_ERROR_TO_OPTION;
		  	ei->onEvent(evdata);
   			return;
   		}
   		else
   		{
   			// Bind to interface
   			if(bind( sd, (struct sockaddr*) &ssa, sizeof(struct sockaddr_in) ) == -1)
   			{
   				close(sd);
   				toSrvMapErr(ifIndex, srv_type); // add to services
				evdata.message = "Failed to bind: " + err2string( strerror(errno) );
				evdata.type = SNM_GM_ERROR_BIND;
			  	ei->onEvent(evdata);
   				return;
   			}
   			else
   			{
   				toSrvMap( ifIndex, srv_type, ref(srv) ); // add to services
   			}
   		}
   	}
    unique_lock<mutex> ulck(srv.mtx);
    if(srv.run_flag) srv.cv.wait_for(ulck, MDNSV4RESOLVER_INIT_TIME_SHIFT);  // Waiting for ARP resolver

    while(srv.run_flag)
    {
    	dsa.sin_addr.s_addr = htonl(INADDR_MDNS_LOCAL_GROUP); // 224.0.0.251
    	mdns_s_buf_size = make_simple_mdns_request(srv_name, mdns_s_buffer);
    	l = sendto( sd, mdns_s_buffer, mdns_s_buf_size, 0,(struct sockaddr*) &dsa, sizeof(dsa) );
    	if(l == -1)
    	{
			evdata.message = "Failed to send: " + err2string( strerror(errno) );
			evdata.type = SNM_GM_ERROR_SEND;
		  	ei->onEvent(evdata);
    		++srv.interrc;
    		continue;
    	}
    	++srv.sbcount;
    	// Collect mDNS nodes
 	    while( srv.run_flag and (l != -1) )
	    {
	    	memset( buffer, 0, sizeof(buffer) );
	    	memset( &psa, 0, sizeof(psa) );	psa_len = sizeof(struct sockaddr_in);
	    	l = recvfrom(sd, buffer, sizeof(buffer), 0, (struct sockaddr*) &psa, &psa_len);
	    	if(l > 0)
	    	{
	    		mdns_hdr = (struct dns_packet_header *) buffer;
	    		if( ( psa.sin_port == HTONS(MDNS_PORT) ) and ( (mdns_hdr->flags & 0xf080) == 0x80 ) ) // mDNS packet, response, no errors
	    		{
	    			++srv.rbcount;
	    			mdns_nodes_ipv4.push_back(psa.sin_addr);
	    		}
	    	}
	    }
    	if(!srv.run_flag) break;
    	// Get info from nodes
	    for(auto node: mdns_nodes_ipv4)
	    {
	    	dsa.sin_addr.s_addr = node.s_addr;
	    	memset( mdns_s_buffer, 0, sizeof(mdns_s_buffer) );
	    	mdns_s_buf_size = make_simple_mdns_request(arpa_ip4_string(node.s_addr), mdns_s_buffer);
	    	l = sendto( sd, mdns_s_buffer, mdns_s_buf_size, 0,(struct sockaddr*) &dsa, sizeof(dsa) );
	    	if(l == -1)
	    	{
				evdata.message = "Failed to send: " + err2string( strerror(errno) );
				evdata.type = SNM_GM_ERROR_SEND;
			  	ei->onEvent(evdata);
	    		++srv.interrc;
	    		continue;
	    	}
	    	++srv.scount;
	    	if(!srv.run_flag) break;
	    	while(l > 0)
	    	{
	    		memset( buffer, 0, sizeof(buffer) );
	    		memset( &psa, 0, sizeof(psa) );	psa_len = sizeof(struct sockaddr_in);
	    		l = recvfrom(sd, buffer, sizeof(buffer), 0, (struct sockaddr*) &psa, &psa_len);
	    		if(!srv.run_flag) break;
	    		if(l > 0)
	    		{
		    		mdns_hdr = (struct dns_packet_header *) buffer;
		    		if( ( psa.sin_port == HTONS(MDNS_PORT) ) and
		    			( (mdns_hdr->flags & 0xf080) == 0x80 ) and
						(psa.sin_addr.s_addr == dsa.sin_addr.s_addr) ) // mDNS packet, response, no errors, correct sender address
		    		{
		    			offset = mdns_s_buf_size;
						offset += mdns_rr_name_len(buffer, offset); // name length of the answer section
						rr_tail = (struct dns_rr_tail *) &buffer[offset];
						if( rr_tail->rrtype == HTONS(DNS_TYPE_PTR) ) // check type
						{
							++srv.rcount;
							offset += sizeof(struct dns_rr_tail);
							domain_name = get_mdns_rr_name(buffer, offset);
							node_name = domain_name.substr( 0, domain_name.find(".local") );
							//cout << "mdnsv4Resolver(): got name: " << domain_name << endl;
							if( srv.run_flag and arpAHelper->getMAC(psa.sin_addr.s_addr, node_mac_addr) )
							{
								if(dbm->toMDNSrow( macBtoS(node_mac_addr).c_str(), node_name.c_str() ) != SQLITE_OK) ++srv.sqlerrc;
							}
							break; // got the name
						}
		    		}
	    		}
	    	} // end while
	    } // end for
	    mdns_nodes_ipv4.clear();
	    if(srv.run_flag)
	    	srv.cv.wait_for(ulck, MDNSV4RESOLVER_SLEEP_TIME);
	    else
	    	break;
    } // end while
	close(sd);
	onReturn(ifIndex, srv_type);
	return;
}
// mDNSv6 resolver
void GMonitor::mdnsv6Resolver(unsigned int ifIndex, uint8_t srv_type)
{
	struct service_record srv;
	int sd, l;
	unsigned short offset;
	struct sockaddr_in6 ssa = {0};
	struct sockaddr_in6 dsa = {0};
	struct sockaddr_in6 psa = {0};
	socklen_t psa_len;
	vector <in6_addr> mdns_nodes_ipv6;
	string domain_name, node_name;
	struct dns_packet_header *mdns_hdr;
	struct dns_rr_tail *rr_tail;
	struct eventData evdata = {SNM_GM_MODULE_NAME, "mdnsv6Resolver", "", 0};

	struct interface ifa_info = actIf[ifIndex]; // get interface info

	char buffer[ifa_info.mtu];

	string srv_name = "_services._dns-sd._udp.local";
    size_t mdns_s_buf_size; // = sizeof(dns_packet_header) + (srv_name.size() + 2) + sizeof(dns_query_tail);
    char mdns_s_buffer[NI_MAXHOST]; // ??? not sure

    dsa.sin6_family = AF_INET6;
    dsa.sin6_port = HTONS(MDNS_PORT);

    ssa.sin6_family = AF_INET6;
    ssa.sin6_port = PORT_ANY;
    ssa.sin6_addr = ifa_info.sin6_addr;
    ssa.sin6_scope_id = ifa_info.sin6_scope_id;

    sd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
   	if(sd == -1)
   	{
   		toSrvMapErr(ifIndex, srv_type); // add to services
		evdata.message = "Failed to create socket descriptor: " + err2string( strerror(errno) );
		evdata.type = SNM_GM_ERROR_SOCKET;
	  	ei->onEvent(evdata);
   	   	return;
   	}
   	else
   	{
   		// Set timeout for protocol
   		struct timeval tv = {.tv_sec = UCAST_REQ_RETRY_TIMEOUT};
   		if(setsockopt( sd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv) ) == -1)
   		{
   			close(sd);
   			toSrvMapErr(ifIndex, srv_type); // add to services
			evdata.message = "Failed to set timeout option: " + err2string( strerror(errno) );
			evdata.type = SNM_GM_ERROR_TO_OPTION;
		  	ei->onEvent(evdata);
   			return;
   		}
   		else
   		{
   			toSrvMap( ifIndex, srv_type, ref(srv) ); // add to services
   		}
   	}

    unique_lock<mutex> ulck(srv.mtx);
    if(srv.run_flag) srv.cv.wait_for(ulck, MDNSV6RESOLVER_INIT_TIME_SHIFT); // Waiting for IPv6 interface to not be tentative

    while(srv.run_flag)
    {
    	if(bind( sd, (struct sockaddr*) &ssa, sizeof(struct sockaddr_in6) ) == 0)
    	{
    		break;
    	}
    	else
    	{
    		++srv.interrc;
    		srv.cv.wait_for( ulck, chrono::seconds(UCAST_REQ_RETRY_TIMEOUT) );
    	}
    }

    while(srv.run_flag)
    {
    	mdns_s_buf_size = make_simple_mdns_request(srv_name, mdns_s_buffer);
        inet_pton(AF_INET6, MDNSV6_LOCAL_GROUP, &dsa.sin6_addr);
    	l = sendto( sd, mdns_s_buffer, mdns_s_buf_size, 0,(struct sockaddr*) &dsa, sizeof(dsa) );
    	if(l == -1)
    	{
			evdata.message = "Failed to send: " + err2string( strerror(errno) );
			evdata.type = SNM_GM_ERROR_SEND;
		  	ei->onEvent(evdata);
    		++srv.interrc;
    		continue;
    	}
    	++srv.sbcount;
    	// Collect mDNS nodes
 	    while( srv.run_flag and (l != -1) )
	    {
	    	memset( buffer, 0, sizeof(buffer) );
	    	memset( &psa, 0, sizeof(psa) );	psa_len = sizeof(struct sockaddr_in6);
	    	l = recvfrom(sd, buffer, sizeof(buffer), 0, (struct sockaddr*) &psa, &psa_len);
	    	if(l > 0)
	    	{
	    		mdns_hdr = (struct dns_packet_header *) buffer;
	    		if( ( psa.sin6_port == HTONS(MDNS_PORT) ) and ( (mdns_hdr->flags & 0xf080) == 0x80 ) ) // mDNS packet, response, no errors
	    		{
    				++srv.rbcount;
    				mdns_nodes_ipv6.push_back(psa.sin6_addr);
	    		}
	    	}
	    }
    	if(!srv.run_flag) break;
    	// Get info from nodes
	    for(auto node: mdns_nodes_ipv6)
	    {
	    	dsa.sin6_addr = node;
	    	memset( mdns_s_buffer, 0, sizeof(mdns_s_buffer) );
	    	mdns_s_buf_size = make_simple_mdns_request(arpa_ip6_string(node), mdns_s_buffer);
	    	l = sendto( sd, mdns_s_buffer, mdns_s_buf_size, 0,(struct sockaddr*) &dsa, sizeof(dsa) );
	    	if(l == -1)
	    	{
				evdata.message = "Failed to send: " + err2string( strerror(errno) );
				evdata.type = SNM_GM_ERROR_SEND;
			  	ei->onEvent(evdata);
	    		++srv.interrc;
	    		continue;
	    	}
	    	++srv.scount;
	    	if(!srv.run_flag) break;
	    	while(l > 0)
	    	{
	    		memset( buffer, 0, sizeof(buffer) );
	    		memset( &psa, 0, sizeof(psa) );	psa_len = sizeof(struct sockaddr_in6);
	    		l = recvfrom(sd, buffer, sizeof(buffer), 0, (struct sockaddr*) &psa, &psa_len);
	    		if(!srv.run_flag) break;
	    		if(l > 0)
	    		{
		    		mdns_hdr = (struct dns_packet_header *) buffer;
		    		if( ( psa.sin6_port == HTONS(MDNS_PORT) ) and
		    			( (mdns_hdr->flags & 0xf080) == 0x80 ) and
						(memcmp( &psa.sin6_addr, &dsa.sin6_addr, sizeof(in6_addr) ) == 0) ) // mDNS packet, response, no errors, correct sender address
		    		{
		    			offset = mdns_s_buf_size;
						offset += mdns_rr_name_len(buffer, offset); // name length of the answer section
						rr_tail = (struct dns_rr_tail *) &buffer[offset];
						if( rr_tail->rrtype == HTONS(DNS_TYPE_PTR) ) // check type
						{
							++srv.rcount;
							offset += sizeof(struct dns_rr_tail);
							domain_name = get_mdns_rr_name(buffer, offset);
							node_name = domain_name.substr( 0, domain_name.find(".local") );
							if(memcmp( &psa.sin6_addr, &ifa_info.sin6_addr, sizeof(in6_addr) ) == 0) // ipv6Listener() deals with the rest nodes
							{
	  		    				if( srv.run_flag and (dbm->toMDNSrow( macBtoS(ifa_info.mac_addr).c_str(), node_name.c_str() ) != SQLITE_OK) )
	  		    				{
	  		    					++srv.sqlerrc;
	  		    				}
							}
							break; // got the name
						}

		    		}
	    		}

	    	} // end while
	    } // end for
	    mdns_nodes_ipv6.clear();
	    if(srv.run_flag)
	    	srv.cv.wait_for(ulck, MDNSV6RESOLVER_SLEEP_TIME);
	    else
	    	break;
    } // end while
	close(sd);
	onReturn(ifIndex, srv_type);
	return;
}
// mDNS listener
void GMonitor::mdnsv4Listener(unsigned int ifIndex, uint8_t srv_type)
{
	struct service_record srv;
	int sd, l;
	unsigned short offset;
	struct sockaddr_in ssa = {0};
	struct sockaddr_in psa;
	socklen_t psa_len;
	struct eventData evdata = {SNM_GM_MODULE_NAME, "mdnsv4Listener", "", 0};

	struct interface ifa_info = actIf[ifIndex]; // get interface info
	class arpAnycastHelper* arpAHelper = arpHlpr.at(ifIndex); // pointer to arpAnycastHelper

	unsigned char buffer[ifa_info.mtu];
	struct dns_packet_header *header = (dns_packet_header *) buffer;
	struct dns_rr_tail *rr_tail;
	string rr_name, rr_domain_name, arpa_ipv4;
	uint16_t rr_type, rr_name_len;
	unsigned char node_mac_addr[ETH_ALEN];

	ssa.sin_family = AF_INET;
	ssa.sin_port = HTONS(MDNS_PORT);
	ssa.sin_addr.s_addr = htonl(INADDR_MDNS_LOCAL_GROUP);

    sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
   	if(sd == -1)
   	{
   		toSrvMapErr(ifIndex, srv_type); // add to services
		evdata.message = "Failed to create socket descriptor: " + err2string( strerror(errno) );
		evdata.type = SNM_GM_ERROR_SOCKET;
	  	ei->onEvent(evdata);
   	   	return;
   	}
   	else
   	{
   		// Set reuse option for reserved port
		int enbl_flag = 1;
		if(setsockopt( sd, SOL_SOCKET, SO_REUSEADDR, &enbl_flag, sizeof(int) ) == -1)
		{
   			close(sd);
   			toSrvMapErr(ifIndex, srv_type); // add to services
			evdata.message = "Failed to set socket option: " + err2string( strerror(errno) );
			evdata.type = SNM_GM_ERROR_OPTION;
		  	ei->onEvent(evdata);
   			return;
   		}
		else
		{
	   		// Set timeout for protocol
	   		struct timeval tv = {.tv_sec = UCAST_REQ_RETRY_TIMEOUT};
	   		if(setsockopt( sd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv) ) == -1)
	   		{
	   			close(sd);
	   			toSrvMapErr(ifIndex, srv_type); // add to services
				evdata.message = "Failed to set timeout option: " + err2string( strerror(errno) );
				evdata.type = SNM_GM_ERROR_TO_OPTION;
			  	ei->onEvent(evdata);
	   			return;
	   		}
	   		else
	   		{
	   			// Bind to interface
	   			struct ifreq if_bind;
	   			strncpy( (char *) &if_bind.ifr_ifrn, ifa_info.if_name, IFNAMSIZ );
	   			if(setsockopt( sd, SOL_SOCKET, SO_BINDTODEVICE, (char *)&if_bind,  sizeof(struct ifreq) ) == -1)
	   			{
	   				close(sd);
	   				toSrvMapErr(ifIndex, srv_type); // add to services
					evdata.message = "Failed to bind to interface: " + err2string( strerror(errno) );
					evdata.type = SNM_GM_ERROR_BIND;
				  	ei->onEvent(evdata);
	   				return;
	   			}
	   			else
	   			{
					// Bind to multicast group
					if(bind( sd, (struct sockaddr*) &ssa, sizeof(struct sockaddr_in) ) == -1)
					{
		   				close(sd);
		   				toSrvMapErr(ifIndex, srv_type); // add to services
						evdata.message = "Failed to bind to multicast group: " + err2string( strerror(errno) );
						evdata.type = SNM_GM_ERROR_BIND_MCG;
					  	ei->onEvent(evdata);
		   				return;
					}
					else
					{
						// Add membership to multicast group
						struct ip_mreqn mreqn;
						mreqn.imr_multiaddr = ssa.sin_addr; 	// multicast group address
						mreqn.imr_address.s_addr = INADDR_ANY;	// use interface address
						mreqn.imr_ifindex = ifIndex; 			// interface number
						if(setsockopt( sd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreqn, sizeof(struct ip_mreqn) ) == -1)
						{
			   				close(sd);
			   				toSrvMapErr(ifIndex, srv_type); // add to services
							evdata.message = "Failed to add membership to multicast group: " + err2string( strerror(errno) );
							evdata.type = SNM_GM_ERROR_ADD_MBSH;
						  	ei->onEvent(evdata);
			   				return;
						}
			   			else
			   			{
			   				toSrvMap( ifIndex, srv_type, ref(srv) ); // add to services
			   			}
					}
	   			}
	   		}
		}
   	}

    while(srv.run_flag)
    {
   		memset( buffer, 0, sizeof(buffer) );
   		memset( &psa, 0, sizeof(psa) );	psa_len = sizeof(struct sockaddr_in);
   		l = recvfrom(sd, buffer, sizeof(buffer), 0, (struct sockaddr*) &psa, &psa_len);
   		if( srv.run_flag and (l > 0) )
   		{
   			++srv.rbcount;
   			offset = 0;
   			if( (header->name_trn_id == 0) and ( (header->flags & 0x0080) > 0 ) ) // requests only
   			{
   				arpa_ipv4 = arpa_ip4_string(psa.sin_addr.s_addr);
   				offset += sizeof(union dns_rr_pointer);
   				offset += sizeof(struct dns_rr_tail);

   				for(uint8_t i=0; i < NTOHS(header->ancount); ++i)
   				{
   					rr_name_len = mdns_rr_name_len( (char *) buffer, offset );
   					rr_tail = (struct dns_rr_tail *) (buffer + offset + rr_name_len);
   					rr_type = NTOHS(rr_tail->rrtype);
   					if(rr_type == DNS_TYPE_PTR)
   					{
   						rr_name = get_mdns_rr_name( (char *) buffer, offset );
  						offset += rr_name_len;
  						offset += sizeof(struct dns_rr_tail);
  						rr_domain_name = get_mdns_rr_name( (char *) buffer, offset );
  						offset += mdns_rr_name_len( (char *) buffer, offset );
  						if(rr_name == arpa_ipv4)
  						{
  							++srv.rcount;
  							rr_domain_name = rr_domain_name.substr( 0, rr_domain_name.find(".local") );
  		    				if( srv.run_flag and arpAHelper->getMAC(psa.sin_addr.s_addr, node_mac_addr) )
  		    				{
  		    					if(dbm->toMDNSrow( macBtoS(node_mac_addr).c_str(), rr_domain_name.c_str() ) != SQLITE_OK) srv.sqlerrc++;
  		    				}
  						}
   					}
   					else
   					{
   						offset += rr_name_len;
   						offset += sizeof(struct dns_rr_tail);
   						offset += NTOHS(rr_tail->rdlenth);
   					}
   				}
   			}
   		}
   		else
   		{
   			continue;
   		}
    } // end while
	close(sd);
	onReturn(ifIndex, srv_type);
	return;
}
// IPv4 multicast listener (mDNS, LLMNR)
void GMonitor::ipv4MCListener(unsigned int ifIndex, uint8_t srv_type)
{
	struct service_record srv;
	int sd, l, offset;
	struct eventData evdata = {SNM_GM_MODULE_NAME, "ipv4MCListener", "", 0};

	struct interface ifa_info = actIf[ifIndex]; // get interface info

	char rbuffer[ifa_info.mtu + 14] = {0};
	struct ethhdr *ethheader = (struct ethhdr *) rbuffer;
	struct iphdr *ipv4header = (struct iphdr *) &rbuffer[sizeof(struct ethhdr)];
	struct udphdr *udp_header;
	struct dns_packet_header *dns_header;
	uint32_t mssg_offset;
	uint16_t type;
	char ip_addr_dot[INET_ADDRSTRLEN] = {0};

	string rr_name, rr_domain_name, arpa_ipv4;
	uint16_t rr_type, rr_name_len;
	struct dns_rr_tail *rr_tail;

	struct packet_mreq  mreq = {0};
	mreq.mr_ifindex = ifa_info.if_index;
	mreq.mr_type = PACKET_MR_ALLMULTI;

	sd = socket( AF_PACKET, SOCK_RAW, HTONS(ETH_P_IP) );
	if(sd == -1)
	{
   		toSrvMapErr(ifIndex, srv_type); // add to services
		evdata.message = "Failed to create socket descriptor: " + err2string( strerror(errno) );
		evdata.type = SNM_GM_ERROR_SOCKET;
	  	ei->onEvent(evdata);
   	   	return;
	}
	else
	{
   		// Set timeout for protocol
   		struct timeval tv = {.tv_sec = UCAST_REQ_RETRY_TIMEOUT};
   		if(setsockopt( sd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv) ) == -1)
   		{
   			close(sd);
   			toSrvMapErr(ifIndex, srv_type); // add to services
			evdata.message = "Failed to set timeout option: " + err2string( strerror(errno) );
			evdata.type = SNM_GM_ERROR_TO_OPTION;
		  	ei->onEvent(evdata);
   			return;
   		}
		else
		{
			// Add multicast membership
			if(setsockopt( sd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq) ) == -1)
			{
				close(sd);
	   			toSrvMapErr(ifIndex, srv_type); // add to services
				evdata.message = "Failed to add multicast membership: " + err2string( strerror(errno) );
				evdata.type = SNM_GM_ERROR_ADD_MBSH;
			  	ei->onEvent(evdata);
	   			return;
			}
			else
			{
				toSrvMap( ifIndex, srv_type, ref(srv) ); // add to services
			}
		}
	}

	while(srv.run_flag)
	{
		memset( rbuffer, 0, sizeof(rbuffer) );
		l = recvfrom(sd, rbuffer, sizeof(rbuffer), 0, NULL, NULL);
		if(l <= 0) continue; // nothing to do
		if(ethheader->h_dest[0] & 0x01) // multicast or broadcast
		{
			++srv.rbcount;
			if( (ethheader->h_dest[5] != 0xfb) and (ethheader->h_dest[5] != 0xfc) ) continue; // simple filter
			if(ipv4header->daddr == MDNS_LOCAL_GROUP) // mDNS
			{
				offset = sizeof(struct ethhdr) + sizeof(struct iphdr);
				if(offset >= l)
				{
					++srv.interrc;
					continue;
				}
				udp_header = (struct udphdr *) &rbuffer[offset];
				if( NTOHS(udp_header->dport) != MDNS_PORT ) continue; // check destination port
				if( (udp_header->len != 0) and (udp4_checksum(ipv4header) != 0) ) // check checksum if available
				{
					++srv.interrc;
					continue;
				}
				offset = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
				if(offset >= l)
				{
					++srv.interrc;
					continue;
				}
				dns_header = (struct dns_packet_header *) &rbuffer[offset];
				if( (dns_header->name_trn_id == 0) and ( (dns_header->flags & 0x0080) > 0 ) ) // requests only
				{
					mssg_offset = offset; // set beginning of mDNS message
	   				arpa_ipv4 = arpa_ip4_string(ipv4header->saddr);
	   				offset += sizeof(union dns_rr_pointer);
	   				offset += sizeof(struct dns_rr_tail);
	   				if(offset >= l)
	   				{
	   					++srv.interrc;
	   					continue;
	   				}
	   				for(uint8_t i=0; i < NTOHS(dns_header->ancount); ++i)
	   				{
	   					rr_name_len = mdns_rr_name_len( (char *) rbuffer, offset );
	   					rr_tail = (struct dns_rr_tail *) &rbuffer[offset + rr_name_len];
	   					rr_type = NTOHS(rr_tail->rrtype);
	   					if(rr_type == DNS_TYPE_PTR)
	   					{
	   						rr_name = get_mdns_rr_name( (char *) rbuffer, offset, mssg_offset );
	   						offset += rr_name_len;
	  						offset += sizeof(struct dns_rr_tail);
	  		   				if(offset >= l)
	  		   				{
	  		   					++srv.interrc;
	  		   					break;
	  		   				}
	  						rr_domain_name = get_mdns_rr_name( (char *) rbuffer, offset, mssg_offset );
	  						offset += mdns_rr_name_len( (char *) rbuffer, offset );
	  		   				if(offset > l)
	  		   				{
	  		   					++srv.interrc;
	  		   					break;
	  		   				}
	  						if(rr_name == arpa_ipv4)
	  						{
	  							++srv.rcount;
	  							//cout << rr_name << endl;
	  							rr_domain_name = rr_domain_name.substr( 0, rr_domain_name.find(".local") );
	  							//cout << rr_domain_name << ", mac = " << macBtoS(ethheader->h_source) << endl << endl;
	  							inet_ntop(AF_INET, &(ipv4header->saddr), ip_addr_dot, INET_ADDRSTRLEN);
	  		    				if( srv.run_flag and (dbm->toARProw(macBtoS(ethheader->h_source).c_str(), ip_addr_dot) != SQLITE_OK) )
	  		    				{
	  		    					++srv.sqlerrc;
	  		    				}
	  		    				if( srv.run_flag and (dbm->toMDNSrow( macBtoS(ethheader->h_source).c_str(), rr_domain_name.c_str() ) != SQLITE_OK) )
	  		    				{
	  		    					++srv.sqlerrc;
	  		    				}
	  						}
	   					}
	   					else
	   					{
	   						offset += rr_name_len;
	   						offset += sizeof(struct dns_rr_tail);
	   						offset += NTOHS(rr_tail->rdlenth);
	   		   				if(offset > l)
	   		   				{
	   		   					++srv.interrc;
	   		   					break;
	   		   				}
	   					}
	   				} // end for

				}
			}
			else if(ipv4header->daddr == LLMNR_LOCAL_GROUP) // LLMNR
			{
				offset = sizeof(struct ethhdr) + sizeof(struct iphdr);
				if(offset >= l)
				{
					++srv.interrc;
					continue;
				}
				udp_header = (struct udphdr *) &rbuffer[offset];
				if(NTOHS(udp_header->dport) != LLMNR_PORT) continue; // check destination port
				if( (udp_header->len != 0) and (udp4_checksum(ipv4header) != 0) ) // check checksum if available
				{
					++srv.interrc;
					continue;
				}
				offset = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
				if(offset >= l)
				{
					++srv.interrc;
					continue;
				}
				dns_header = (struct dns_packet_header *) &rbuffer[offset];
				mssg_offset = offset; // set the beginning of LLMNR message
				if( (dns_header->flags == 0) and (dns_header->qdcount == 0x0100) ) // standard query only
				{
	   				offset += sizeof(union dns_rr_pointer);
	   				offset += sizeof(struct dns_rr_tail);
	   				if(offset >= l)
	   				{
	   					++srv.interrc;
	   					continue;
	   				}
	   				rr_name_len = mdns_rr_name_len( (char *) rbuffer, offset );
	   				rr_domain_name = get_mdns_rr_name(rbuffer, offset, mssg_offset);
	   				offset += rr_name_len;
	   				if(offset >= l)
	   				{
	   					++srv.interrc;
	   					continue;
	   				}
	   				type = *((uint16_t *) &rbuffer[offset]);
	   				if(type == 0xFF00) // type == ANY
	   				{
	   					++srv.rcount;
						inet_ntop(AF_INET, &(ipv4header->saddr), ip_addr_dot, INET_ADDRSTRLEN);
	    				if( srv.run_flag and (dbm->toARProw(macBtoS(ethheader->h_source).c_str(), ip_addr_dot) != SQLITE_OK) )
	    				{
	    					++srv.sqlerrc;
	    				}
	    				if( srv.run_flag and (dbm->toLLMNRrow( macBtoS(ethheader->h_source).c_str(), rr_domain_name.c_str() ) != SQLITE_OK) )
	    				{
	    					++srv.sqlerrc;
	    				}
	   				}
				}
			}
		}
	} // end while
	// Clear multicast membership
	if(setsockopt( sd, SOL_PACKET, PACKET_DROP_MEMBERSHIP, &mreq, sizeof(mreq) ) == -1)
	{
		evdata.message = "Failed to clear multicast membership: " + err2string( strerror(errno) );
		evdata.type = SNM_GM_ERROR_CLEAR_MBSH;
	  	ei->onEvent(evdata);
	}
	close(sd);
	onReturn(ifIndex, srv_type);
	return;
}
// IPv6 listener (ICMP6, mDNS, LLMNR)
void GMonitor::ipv6Listener(unsigned int ifIndex, uint8_t srv_type)
{
	struct service_record srv;
	int sd, l, offset;
	char rbuffer[ETH_FRAME_LEN] = {0};
	struct eventData evdata = {SNM_GM_MODULE_NAME, "ipv6Listener", "", 0};
	struct ethhdr *ethheader = (struct ethhdr *) rbuffer;
	struct ip6_hdr *ipv6header = (struct ip6_hdr *) &rbuffer[sizeof(struct ethhdr)];
	struct icmpv6_hdr *icmpv6_header;
	struct udphdr *udp_header;
	struct dns_packet_header *mdns_hdr;

	string rr_name, rr_domain_name, arpa_ipv6;
	uint16_t rr_name_len;
	struct dns_rr_tail *rr_tail;

	char ip6_addr_dot[INET6_ADDRSTRLEN];
	uint32_t mssg_offset;
	uint16_t type;

	struct interface ifa_info = actIf[ifIndex]; // get interface info

	struct sockaddr_ll ssa = {0};
	ssa.sll_family = AF_PACKET;
	ssa.sll_protocol = HTONS(ETH_P_IPV6);
	ssa.sll_ifindex = ifIndex;

	sd = socket( AF_PACKET, SOCK_RAW, HTONS(ETH_P_IPV6) );
	if(sd == -1)
	{
		toSrvMapErr(ifIndex, srv_type); // add to services
		evdata.message = "Failed to create socket descriptor: " + err2string( strerror(errno) );
		evdata.type = SNM_GM_ERROR_SOCKET;
	  	ei->onEvent(evdata);
	   	return;
	}
	else
	{
		//Bind to the interface
		if(bind( sd, (struct sockaddr*) &ssa, sizeof(struct sockaddr_ll) ) == -1)
		{
			close(sd);
			toSrvMapErr(ifIndex, srv_type); // add to services
			evdata.message = "Failed to bind: " + err2string( strerror(errno) );
			evdata.type = SNM_GM_ERROR_BIND;
		  	ei->onEvent(evdata);
			return;
		}
		else
		{
			// Set timeout for protocol
			struct timeval tv = {.tv_sec = UCAST_REQ_RETRY_TIMEOUT};
			if(setsockopt( sd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv) ) == -1)
			{
				close(sd);
				toSrvMapErr(ifIndex, srv_type); // add to services
				evdata.message = "Failed to set timeout option: " + err2string( strerror(errno) );
				evdata.type = SNM_GM_ERROR_TO_OPTION;
			  	ei->onEvent(evdata);
				return;
			}
			else
			{
				toSrvMap( ifIndex, srv_type, ref(srv) ); // add to services
			}
		}
	}

	while(srv.run_flag)
	{
		memset( rbuffer, 0, sizeof(rbuffer) );
		l = recvfrom(sd, rbuffer, ETH_FRAME_LEN, 0, NULL, NULL);

		if(l <= 0) continue; // nothing to do

		if(memcmp(&ethheader->h_dest, ifa_info.mac_addr, ETH_ALEN) == 0) // unicast packet
		{
			if(ipv6header->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_UDP) continue; // filter non-udp unicast traffic
		}

		++srv.rbcount;

		if(ipv6header->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_ICMPV6) // ICMPv6 packet
		{
			icmpv6_header = (struct icmpv6_hdr *) &rbuffer[sizeof(struct ethhdr) + sizeof(struct ip6_hdr)];
			if(icmpv6_checksum(ipv6header) != 0) // errors in the packet
			{
					++srv.interrc;
					continue;
			}
			if(icmpv6_header->type == 133) // Router solicitation
			{
				++srv.rcount;
				inet_ntop( AF_INET6, &(ipv6header->ip6_src), ip6_addr_dot, sizeof(ip6_addr_dot) );
				if( srv.run_flag and (dbm->toIPV6row( macBtoS(ethheader->h_source).c_str(), ip6_addr_dot, ifIndex ) != SQLITE_OK) ) ++srv.sqlerrc;
			}
			if(icmpv6_header->type == 134) // Router advertisement
			{
				++srv.rcount;
				inet_ntop( AF_INET6, &(ipv6header->ip6_src), ip6_addr_dot, sizeof(ip6_addr_dot) );
				if( srv.run_flag and (dbm->toIPV6row( macBtoS(ethheader->h_source).c_str(), ip6_addr_dot, ifIndex) != SQLITE_OK) ) ++srv.sqlerrc;
			}
/* Not tested
			if( icmpv6_header->type == 136 ) // Neighbor advertisement
			{
				++srv.rcount;
				struct icmpv6_type_136 *info = (struct icmpv6_type_136 *) &rbuffer[sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct icmpv6_hdr)];
				cout << "Neighbor advertisement" << endl;
				inet_ntop( AF_INET6, &(info->taddr), ip6_addr_dot, sizeof(ip6_addr_dot) );
				cout << "Target address: " << ip6_addr_dot << endl;
				cout << "Length: " << NTOHS(ipv6header->payload_len) << endl;
				cout << "MAC address: " << macBtoS(info->lladdr) << endl;
				//if( srv.run_flag and ( toIPV6row( mdb, smtph, macBtoS(info->lladdr).c_str(), ip6_addr_dot, ifIndex ) != SQLITE_OK ) ) ++srv.sqlerrc;
			}
*/

		}
		else
		{
			if(ipv6header->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_UDP) // UDP packet
			{
				if( udp6_checksum(ipv6header) != 0 ) // errors in the packet
				{
					++srv.interrc;
					continue;
				}
				offset = sizeof(struct ethhdr) + sizeof(struct ip6_hdr);
				udp_header = (struct udphdr *) &rbuffer[offset];
				if( udp_header->dport == HTONS(LLMNR_PORT) ) // LLMNR proto
				{
					offset += sizeof(struct udphdr);
					mdns_hdr = (struct dns_packet_header *) &rbuffer[offset];
					mssg_offset = offset; // set the beginning of LLMNR message
					if( (mdns_hdr->flags == 0) and (mdns_hdr->qdcount == 0x0100) ) // standard query only
					{
						offset += sizeof(struct dns_packet_header);
		   				rr_name_len = mdns_rr_name_len(rbuffer, offset);
		   				rr_domain_name = get_mdns_rr_name(rbuffer, offset, mssg_offset);
		   				offset += rr_name_len;
		   				type = *((uint16_t *) &rbuffer[offset]);
		   				if(type == 0xFF00) // type == ANY
		   				{
		   					++srv.rcount;
		   					inet_ntop( AF_INET6, &(ipv6header->ip6_src), ip6_addr_dot, sizeof(ip6_addr_dot) );
  		    				if( srv.run_flag and (dbm->toIPV6row( macBtoS(ethheader->h_source).c_str(), ip6_addr_dot, ifIndex ) != SQLITE_OK) )
  		    				{
  		    					++srv.sqlerrc;
  		    				}
		    				if( srv.run_flag and (dbm->toLLMNRrow( macBtoS(ethheader->h_source).c_str(), rr_domain_name.c_str() ) != SQLITE_OK) )
		    				{
		    					++srv.sqlerrc;
		    				}
		   				}
					}
				}
				else if( udp_header->sport == HTONS(MDNS_PORT) ) // mDNS proto
				{
					offset += sizeof(struct udphdr);
					mdns_hdr = (struct dns_packet_header *) &rbuffer[offset];
					if( (mdns_hdr->name_trn_id == 0) and ( (mdns_hdr->flags & 0xf080) == 0x80 ) ) // responses only
					{
						mssg_offset = offset; // set beginning of mDNS message
						arpa_ipv6 = arpa_ip6_string(ipv6header->ip6_src);
						offset += sizeof(struct dns_packet_header);
						if(NTOHS(mdns_hdr->qdcount) > 0)
						{
							rr_name_len = mdns_rr_name_len(rbuffer, offset);
							offset += rr_name_len;
							offset += sizeof(struct dns_query_tail);
						}
		   				for(uint8_t i=0; i < NTOHS(mdns_hdr->ancount); ++i)
		   				{
		   					rr_name_len = mdns_rr_name_len(rbuffer, offset);
		   					rr_tail = (struct dns_rr_tail *) &rbuffer[offset + rr_name_len];
		   					rr_name = get_mdns_rr_name(rbuffer, offset, mssg_offset);
		   					if( rr_tail->rrtype == HTONS(DNS_TYPE_PTR) ) // check type
		   					{
		   						rr_name = get_mdns_rr_name(rbuffer, offset, mssg_offset);
		   						offset += rr_name_len;
		  						offset += sizeof(struct dns_rr_tail);
		  						rr_domain_name = get_mdns_rr_name(rbuffer, offset, mssg_offset);
		  						offset += mdns_rr_name_len(rbuffer, offset);
		  						if(rr_name == arpa_ipv6)
		  						{
		  							++srv.rcount;
		  							rr_domain_name = rr_domain_name.substr( 0, rr_domain_name.find(".local") );
		  							inet_ntop( AF_INET6, &(ipv6header->ip6_src), ip6_addr_dot, sizeof(ip6_addr_dot) );
		  		    				if( srv.run_flag and (dbm->toIPV6row( macBtoS(ethheader->h_source).c_str(), ip6_addr_dot, ifIndex ) != SQLITE_OK) )
		  		    				{
		  		    					++srv.sqlerrc;
		  		    				}
		  		    				if( srv.run_flag and (dbm->toMDNSrow( macBtoS(ethheader->h_source).c_str(), rr_domain_name.c_str() ) != SQLITE_OK) )
		  		    				{
		  		    					++srv.sqlerrc;
		  		    				}
		  							break;
		  						}
		   					}
		   					else
		   					{
		   						offset += rr_name_len;
		   						offset += sizeof(struct dns_rr_tail);
		   						offset += NTOHS(rr_tail->rdlenth);
		   					}
		   				} // end for
					}
				}
			}
		}
	} // end while
	close(sd);
	onReturn(ifIndex, srv_type);
	return;
}
// UPnP resolver
upnp_device_info* GMonitor::getUPnPDeviceInfo(struct uri_data *uri, in_addr if_ipv4_addr)
{
	int sd, l;
	struct eventData evdata = {SNM_GM_MODULE_NAME, "getUPnPDeviceInfo", "", 0};
	struct sockaddr_in ssa = {0}, dsa = {0};
	const char *sbuffer;
	char rbuffer[UPNP_TCP_REPLY_BUFFER_SIZE] = {0};
	stringstream req;
	string request, reply;
	static __thread struct upnp_device_info *dev_info;

	dsa.sin_family = AF_INET;
	dsa.sin_addr.s_addr = inet_addr( uri->host.c_str() );
	dsa.sin_port = htons( (uint16_t) stoi(uri->port) );

	ssa.sin_family = AF_INET;
	ssa.sin_port = PORT_ANY;
	ssa.sin_addr = if_ipv4_addr;

	// Open socket
	sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(sd == -1)
	{
		evdata.message = "Failed to create socket descriptor: " + err2string( strerror(errno) );
		evdata.type = SNM_GM_ERROR_SOCKET;
	  	ei->onEvent(evdata);
	    return nullptr;
	}
    // Set timeout for protocol
    struct timeval tcp_tv = {.tv_sec = UPNP_TCP_UCAST_REQ_RETRY_TIMEOUT};
    if(setsockopt( sd, SOL_SOCKET, SO_RCVTIMEO, &tcp_tv, sizeof(tcp_tv) ) == -1)
    {
    	close(sd);
		evdata.message = "Failed to set timeout option: " + err2string( strerror(errno) );
		evdata.type = SNM_GM_ERROR_TO_OPTION;
	  	ei->onEvent(evdata);
    	return nullptr;
    }
    // Bind socket to interface
    if(bind( sd, (struct sockaddr*) &ssa, sizeof(ssa) ) == -1)
    {
    	close(sd);
		evdata.message = "Failed to bind: " + err2string( strerror(errno) );
		evdata.type = SNM_GM_ERROR_BIND;
	  	ei->onEvent(evdata);
     	return nullptr;
    }
    // Connect to host
    if(connect( sd, (struct sockaddr*) &dsa, sizeof(dsa) ) == -1)
    {
    	//cout << "getUPnPDeviceInfo(): Failed to connect to host: " << strerror(errno) << endl; // Not an error, debug only
    	close(sd);
    	return nullptr;
    }

    req << "GET " << uri->path << " HTTP/1.1\r\n";
    req	<< "HOST: " << uri->host << ":" << uri->port << "\r\n";
    req << "ACCEPT-LANGUAGE: " << "en_US,en;q=0.5\r\n";
    req << "\r\n";
    request = req.str();
    sbuffer = request.c_str();

    l = send(sd, sbuffer, strlen(sbuffer), MSG_NOSIGNAL) ;
    if(l <= 0) // error or connection closed
    {
    	//cout << "getUPnPDeviceInfo(): Failed to send" << endl; // Not an error, debug only
    	close(sd);
    	return nullptr;
    }

    l = recv(sd, rbuffer, sizeof(rbuffer), MSG_WAITALL);

    // Shutdown TCP connection
    close(sd);

    if(l <= 0)
    {
       	//cout << "getUPnPDeviceInfo(): No response from host" << endl; // Not an error, debug only
       	return nullptr;
    }

   	reply = string(rbuffer);

    if( checkHTTPStatusCode(reply) )
    {
   		dev_info = getXMLInfo(reply);
   	}
   	else
   	{
   		//cout << "getUPnPDeviceInfo(): HTTP error" << endl; // Not an error, debug only
      	return nullptr;
    }
    return dev_info;
}
//
void GMonitor::upnpv4Resolver(unsigned int ifIndex, uint8_t srv_type)
{
	struct service_record srv;
	int sd, l;
	struct eventData evdata = {SNM_GM_MODULE_NAME, "upnpv4Resolver", "", 0};
	char *sbuffer;
	struct sockaddr_in psa = {0};
	socklen_t psa_len;
	struct sockaddr_in sa = {0}, sa_out = {0};
	socklen_t sa_out_len;
	stringstream mstr;
	string request_mssg, location;
	map< string, pair<string, string> > xml_links;
	unsigned char node_mac_addr[ETH_ALEN];
	struct uri_data *uri;
	struct upnp_device_info *dev_info;
	string node_descr, node_url, node_urn;

	struct interface ifa_info = actIf[ifIndex]; // get interface info
	class arpAnycastHelper* arpAHelper = arpHlpr.at(ifIndex); // pointer to arpAnycastHelper

	char rbuffer[ifa_info.mtu];

	sa.sin_family = AF_INET;
	sa.sin_port = HTONS(SSDP_MULTICAST_PORT);
	sa.sin_addr.s_addr = htonl(INADDR_SSDP_LOCAL_GROUP);

	sa_out.sin_family = AF_INET;
	sa_out.sin_port = PORT_ANY;
	sa_out.sin_addr = ifa_info.ip_addr;
	sa_out_len = sizeof(sa_out);

	// Open socket
	sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(sd == -1)
	{
		toSrvMapErr(ifIndex, srv_type); // add to services
		evdata.message = "Failed to create socket descriptor: " + err2string( strerror(errno) );
		evdata.type = SNM_GM_ERROR_SOCKET;
	  	ei->onEvent(evdata);
	   	return;
	}
	else
   	{
		// Set timeout for protocol
   		struct timeval tv = {.tv_sec = UCAST_REQ_RETRY_TIMEOUT};
   		if(setsockopt( sd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv) ) == -1)
   		{
   			close(sd);
   			toSrvMapErr(ifIndex, srv_type); // add to services
   			evdata.message = "Failed to set timeout option: " + err2string( strerror(errno) );
   			evdata.type = SNM_GM_ERROR_TO_OPTION;
   		  	ei->onEvent(evdata);
   			return;
   		}
   		else
   		{
   			// Set TTL
   			int ttl = 2; // TTL should be 2 by default
   			if( setsockopt(sd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) )
   			{
   				close(sd);
   				toSrvMapErr(ifIndex, srv_type); // add to services
   				evdata.message = "Failed to set socket option: " + err2string( strerror(errno) );
   				evdata.type = SNM_GM_ERROR_OPTION;
   			  	ei->onEvent(evdata);
   				return;
   			}
   			else
   			{
   				// Bind socket to interface
   				if(bind( sd, (struct sockaddr*) &sa_out, sizeof(sa_out) ) == -1)
   				{
   					close(sd);
   					toSrvMapErr(ifIndex, srv_type); // add to services
   					evdata.message = "Failed to bind: " + err2string( strerror(errno) );
   					evdata.type = SNM_GM_ERROR_BIND;
   				  	ei->onEvent(evdata);
   					return;
   				}
   				else
   				{
   					//Get socket port
   					if(getsockname(sd, (struct sockaddr*) &sa_out, &sa_out_len) == -1)
   					{
   						close(sd);
   						toSrvMapErr(ifIndex, srv_type); // add to services
   						evdata.message = "Failed to get socket info: " + err2string( strerror(errno) );
	   					evdata.type = SNM_GM_ERROR_GET_SINFO;
	   				  	ei->onEvent(evdata);
   						return;
   					}
   					else
   						toSrvMap( ifIndex, srv_type, ref(srv) ); // add to services
   				}
   			}
   		}
   	}


    // Generate UPnP multicast query string
    mstr << SSDP_SEARCH_MESSAGE;
    mstr << "HOST: " << inet_ntoa(sa_out.sin_addr) << ":" << ntohs(sa_out.sin_port) << "\r\n";
    mstr << "MAN: " << "\"ssdp:discover\"\r\n";
    mstr << "ST: " << "ssdp:all\r\n";
    mstr << "MX: 1 \r\n";	// use always!
    mstr << "\r\n";
    request_mssg = mstr.str();

    unique_lock<mutex> ulck(srv.mtx);
    if(srv.run_flag) srv.cv.wait_for(ulck, UPNPV4RESOLVER_INIT_SLEEP_TIME);  // Waiting for ARP resolver

    while(srv.run_flag)
    {
        sbuffer = (char *) request_mssg.c_str();
        l = sendto( sd, sbuffer, strlen(sbuffer), 0, (struct sockaddr*) &sa, sizeof(sa) );
        if(l == -1)
        {
			evdata.message = "Failed to send: " + err2string( strerror(errno) );
			evdata.type = SNM_GM_ERROR_SEND;
		  	ei->onEvent(evdata);
        	continue;
	    }
        srv.sbcount++;
        xml_links.clear();

        while( srv.run_flag and (l != -1) )
        {
        	memset( rbuffer, 0, sizeof(rbuffer) );
        	memset( &psa, 0, sizeof(psa) );	psa_len = sizeof(struct sockaddr_in);
        	l = recvfrom(sd, rbuffer, sizeof(rbuffer), 0,(struct sockaddr*) &psa, &psa_len);
        	if(!srv.run_flag) break;
        	if(l > 0)
        	{
        		srv.rbcount++;
        		if(psa.sin_family == AF_INET)
        		{
        			location = getLocationUrl(rbuffer);
        			if( !location.empty() )
        			{
        				auto res = xml_links.insert( make_pair( location,
        											 make_pair( string( inet_ntoa(psa.sin_addr) ), string() ) ) );
        				if(res.second)
        				{
        					if( srv.run_flag and arpAHelper->getMAC(psa.sin_addr.s_addr, node_mac_addr) )
        					{
        						res.first->second.second = macBtoS(node_mac_addr);
        					}
        					else
        					{
        						xml_links.erase(res.first);
        					}
        				}
        			}
        		}
        	}
        } // end collecting UPnP devices

        if(!srv.run_flag) break;

        // http
        for(auto node: xml_links)
        {
        	node_url = dbm->getUPNPurl(node.second.second);
        	if( !node_url.empty() )
        	{
        		if( getURN(node_url) == getURN(node.first) )
        		{
        			if(dbm->updUPNProw(node.second.second, node.first) != SQLITE_OK) srv.sqlerrc++;
        			continue;
        		}
        	}
        	if(!srv.run_flag) break;
        	// XML parsing
        	uri = parseURL(node.first);
        	if(uri->host == node.second.first) // HTTP address sanity check
        	{
        		dev_info = getUPnPDeviceInfo(uri, ifa_info.ip_addr);
        		srv.scount++;
        		if(dev_info != nullptr)
        		{
        			node_descr = dev_info->manufacturer + " " + dev_info->modelDescription;
        			srv.rcount++;
        		}
        		else
        			continue;
        	}
        	else
        	{
    			evdata.message = "UPnP HTTP address problem for host: " + uri->host;
    			evdata.type = SNM_GM_ERROR_HTTP_ADDR;
    		  	ei->onEvent(evdata);
        		continue;
        	}
        	if(!srv.run_flag) break;
        	if( node_url.empty() )
        	{
        		if(dbm->newUPNProw(node.second.second, node_descr, node.first) != SQLITE_OK) srv.sqlerrc++;
        	}
        	else
        	{
        		if(dbm->updUPNProw(node.second.second, node_descr, node.first) != SQLITE_OK) srv.sqlerrc++;
        	}

        }
        if(srv.run_flag)
        	srv.cv.wait_for(ulck, UPNPV4RESOLVER_SLEEP_TIME);
        else
          	break;
    }
    close(sd);
	onReturn(ifIndex, srv_type);
    return;
}
// LLDP
void GMonitor::lldpReceiver(unsigned int ifIndex, uint8_t srv_type)
{
	struct service_record srv;
	int sd, l, offset;
	struct eventData evdata = {SNM_GM_MODULE_NAME, "lldpReceiver", "", 0};
	unsigned char rbuffer[ETH_FRAME_LEN] = {0};
	struct ethhdr *ethheader = (struct ethhdr *) rbuffer;
	uint8_t type;
	uint16_t len;
	string sys_name;

	struct sockaddr_ll ssa = {0};
	ssa.sll_family = AF_PACKET;
	ssa.sll_protocol = HTONS(ETH_P_LLDP);
	ssa.sll_ifindex = ifIndex;

	struct packet_mreq  mreq = {0};
	mreq.mr_ifindex = ifIndex;
	mreq.mr_type = PACKET_MR_ALLMULTI;

	sd = socket( AF_PACKET, SOCK_RAW, HTONS(ETH_P_LLDP) );
	if(sd == -1)
	{
		toSrvMapErr(ifIndex, srv_type); // add to services
		evdata.message = "Failed to create socket descriptor: " + err2string( strerror(errno) );
		evdata.type = SNM_GM_ERROR_SOCKET;
	  	ei->onEvent(evdata);
	   	return;
	}
	else
	{
		//Bind to the interface
		if(bind( sd, (struct sockaddr*) &ssa, sizeof(struct sockaddr_ll) ) == -1)
		{
			close(sd);
			toSrvMapErr(ifIndex, srv_type); // add to services
			evdata.message = "Failed to bind: " + err2string( strerror(errno) );
			evdata.type = SNM_GM_ERROR_BIND;
			ei->onEvent(evdata);
			return;
		}
		else
		{
			// Set timeout for protocol
			struct timeval tv = {.tv_sec = UCAST_REQ_RETRY_TIMEOUT};
			if(setsockopt( sd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv) ) == -1)
			{
				close(sd);
				toSrvMapErr(ifIndex, srv_type); // add to services
	   			evdata.message = "Failed to set timeout option: " + err2string( strerror(errno) );
	   			evdata.type = SNM_GM_ERROR_TO_OPTION;
	   		  	ei->onEvent(evdata);
				return;
			}
			else
			{
				// Add multicast membership
				if(setsockopt( sd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq) ) == -1)
				{
					close(sd);
					toSrvMapErr(ifIndex, srv_type); // add to services
					evdata.message = "Failed to add multicast membership: " + err2string( strerror(errno) );
					evdata.type = SNM_GM_ERROR_ADD_MBSH;
				  	ei->onEvent(evdata);
					return;
				}
				else
					toSrvMap(ifIndex, srv_type, srv); // add to services
			}
		}
	}

	while(srv.run_flag)
	{
		memset( rbuffer, 0, sizeof(rbuffer) );
		l = recvfrom(sd, rbuffer, sizeof(rbuffer), 0, NULL, NULL);
		if( srv.run_flag and (l != -1) )
		{
			srv.rbcount++;
			//cout << "Interface: " << ifIndex << " " << macBtoS( ethheader->h_source) << " " << macBtoS( ethheader->h_dest) << endl;
			sys_name.clear();
			offset = ETH_HLEN;
			do
			{
				type = rbuffer[offset] >> 1;
				len = (rbuffer[offset] & 1)*256 + rbuffer[offset + 1];
				if(type == 5) // System name
				{
					sys_name.append( (const char *) &rbuffer[offset + 2], len );
					//cout << "Name: " << sys_name << endl;
					if(srv.run_flag)
						if(dbm->toLLDProw(macBtoS(ethheader->h_source), sys_name) != SQLITE_OK) srv.sqlerrc++;
					break;
				}
				offset += len + 2;
			} while(type != 0);
		}
	}
	// Clear multicast membership
	if(setsockopt( sd, SOL_PACKET, PACKET_DROP_MEMBERSHIP, &mreq, sizeof(mreq) ) == -1)
	{
		evdata.message = "Failed to clear multicast membership: " + err2string( strerror(errno) );
		evdata.type = SNM_GM_ERROR_CLEAR_MBSH;
	  	ei->onEvent(evdata);
	}
	close(sd);
	onReturn(ifIndex, srv_type);
	return;
}
// DHCPv4 listeners for all interfaces
void GMonitor::dhcpv4ListenerClient(uint8_t srv_type)
{
	struct service_record srv;
	int sd, l;
	struct eventData evdata = {SNM_GM_MODULE_NAME, "dhcpv4ListenerClient", "", 0};
	uint8_t rbuffer[1500] = {0};
	struct dhcp_header *dhcp_hdr = (struct dhcp_header *) rbuffer;
	char host_name[256], vendor_id[256]; // max option length 255 octets + \0
	string params, options;
	uint16_t offset;
	uint8_t opt, len, mssg_type;
	const uint32_t magic_cookie = htonl(MAGIC_COOKIE);

	struct sockaddr_in dsa = {0};
	//struct sockaddr_in psa;
	//socklen_t psa_len;

	dsa.sin_family = AF_INET;
    dsa.sin_port = HTONS(67);
    dsa.sin_addr.s_addr = INADDR_ANY;

    sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
   	if(sd == -1)
   	{
   		toSrvMapErr(ZERO_IF, srv_type); // add to services
		evdata.message = "Failed to create socket descriptor: " + err2string( strerror(errno) );
		evdata.type = SNM_GM_ERROR_SOCKET;
	  	ei->onEvent(evdata);
   	   	return;
   	}
   	else
   	{
   		// Set timeout for protocol
   		struct timeval tv = {.tv_sec = UCAST_REQ_RETRY_TIMEOUT};
   		if(setsockopt( sd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv) ) == -1)
   		{
   			close(sd);
   			toSrvMapErr(ZERO_IF, srv_type); // add to services
   			evdata.message = "Failed to set timeout option: " + err2string( strerror(errno) );
   			evdata.type = SNM_GM_ERROR_TO_OPTION;
   		  	ei->onEvent(evdata);
   			return;
   		}
   		else
   		{
   			// Set reuse option for reserved port
   			int enbl_flag = 1;
   			if(setsockopt( sd, SOL_SOCKET, SO_REUSEADDR, &enbl_flag, sizeof(int) ) == -1)
   			{
   				close(sd);
	   			toSrvMapErr( ZERO_IF, srv_type ); // add to services
				evdata.message = "Failed to set socket option: " + err2string( strerror(errno) );
				evdata.type = SNM_GM_ERROR_OPTION;
			  	ei->onEvent(evdata);
	   			return;
   			}
   			else
   			{
   				// Bind to interface
   				if(bind( sd, (struct sockaddr*) &dsa, sizeof(struct sockaddr_in) ) == -1)
   				{
   					close(sd);
   					toSrvMapErr(ZERO_IF, srv_type); // add to services
   					evdata.message = "Failed to bind: " + err2string( strerror(errno) );
   					evdata.type = SNM_GM_ERROR_BIND;
   					ei->onEvent(evdata);
   					return;
   				}
   				else
   				{
   					toSrvMap( ZERO_IF, srv_type, ref(srv) ); // add to services
   				}
   			}
   		}
   	}

	while(srv.run_flag)
	{
		l = recvfrom(sd, rbuffer, sizeof(rbuffer), 0, NULL, NULL);
		if(!srv.run_flag) break;
		if(l != -1)
		{
			srv.rbcount++;
			//cout << getLocalTime() << " Received client message: " << l << " from: " <<  inet_ntoa(psa.sin_addr) << endl;
			//cout << "ciaddr: " << inet_ntoa(dhcp_hdr->ciaddr) << " yiaddr: " << inet_ntoa(dhcp_hdr->yiaddr) << endl;
			if( (dhcp_hdr->op == 1) and (dhcp_hdr->hlen == 6) and (dhcp_hdr->magic_cookie == magic_cookie) ) // packet error check
			{
				//cout << "MAC: " << macBtoS(dhcp_hdr->chaddr) << endl;
				if(srv.run_flag)
				{
					if(dbm->toARProw( macBtoS(dhcp_hdr->chaddr).c_str(), "" ) != SQLITE_OK) srv.sqlerrc++;
				}
				else break;
				offset = sizeof(dhcp_header);
				memset( host_name, 0, sizeof(host_name) );
				memset( vendor_id, 0, sizeof(vendor_id) );
				params = ""; options = "";
				mssg_type = 0;
				while(rbuffer[offset] != 255)
				{
					opt = rbuffer[offset++];
					len = rbuffer[offset++];
					if(len == 0) break; // options error check
					//cout << "Option: " << (int) opt << " " << (int) len << endl;
					options += to_string(opt) + ","; // number to letter conversion
					if(opt == DHCP_OPT_MSSG_TYPE)
					{
						mssg_type = rbuffer[offset];
						//cout << "Message type: " << (int) mssg_type << endl;
						if(mssg_type != DHCPREQUEST) break;
					}
					if(opt == DHCP_OPT_HOST_NAME)
					{
						memcpy(host_name, &rbuffer[offset], len);
						//cout << "Host name: " << host_name << endl;
					}
					if(opt == DHCP_OPT_VNDR_CLASS_ID)
					{
						memcpy(vendor_id, &rbuffer[offset], len);
						//cout << "Vendor identifier: " << vendor_id << endl;
					}
					if(opt == DHCP_OPT_PARAM_REQ_LST)
					{
						for( short i = 0; i < len; i++ )
						{
							params += to_string(rbuffer[offset + i]); // number to letter conversion
							if( i < (len - 1) ) params += ",";
						}
						//cout << "Parameters: " << params << endl;
					}
					offset += len;
					if( offset > sizeof(rbuffer) ) break; // options error check
				}
				if( srv.run_flag and (mssg_type == DHCPREQUEST) )
				{
					options.pop_back();
					//cout << "Options: " << options << endl;
					if(dbm->toDHCPv4row(macBtoS(dhcp_hdr->chaddr), host_name, vendor_id, params, options) != SQLITE_OK)
					{
						srv.sqlerrc++;
					}
				}
			}
		}
	}
	close(sd);
	onReturn(ZERO_IF, srv_type);
	return;
}
//
void GMonitor::dhcpv4ListenerServer(uint8_t srv_type)
{
	struct service_record srv;
	int sd, l;
	struct eventData evdata = {SNM_GM_MODULE_NAME, "dhcpv4ListenerServer", "", 0};
	uint8_t rbuffer[1500] = {0};
	struct dhcp_header *dhcp_hdr = (struct dhcp_header *) rbuffer;
	uint16_t offset, len;
	uint8_t opt;
	const uint32_t magic_cookie = htonl(MAGIC_COOKIE);

	struct sockaddr_in dsa = {0};
	//struct sockaddr_in psa;
	//socklen_t psa_len;

	dsa.sin_family = AF_INET;
    dsa.sin_port = HTONS(68);
    dsa.sin_addr.s_addr = INADDR_ANY;

    sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
   	if(sd == -1)
   	{
   		toSrvMapErr(ZERO_IF, srv_type); // add to services
		evdata.message = "Failed to create socket descriptor: " + err2string( strerror(errno) );
		evdata.type = SNM_GM_ERROR_SOCKET;
	  	ei->onEvent(evdata);
   	   	return;
   	}
   	else
   	{
   		// Set timeout for protocol
   		struct timeval tv = {.tv_sec = UCAST_REQ_RETRY_TIMEOUT};
   		if(setsockopt( sd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv) ) == -1)
   		{
   			close(sd);
   			toSrvMapErr(ZERO_IF, srv_type); // add to services
   			evdata.message = "Failed to set timeout option: " + err2string( strerror(errno) );
   			evdata.type = SNM_GM_ERROR_TO_OPTION;
   		  	ei->onEvent(evdata);
   			return;
   		}
   		else
   		{
   			// Set reuse option for reserved port
   			int enbl_flag = 1;
   			if( setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &enbl_flag, sizeof(int) ) == -1)
   			{
   				close(sd);
	   			toSrvMapErr( ZERO_IF, srv_type ); // add to services
				evdata.message = "Failed to set socket option: " + err2string( strerror(errno) );
				evdata.type = SNM_GM_ERROR_OPTION;
			  	ei->onEvent(evdata);
	   			return;
   			}
   			else
   			{
   				// Bind to interface
   				if(bind( sd, (struct sockaddr*) &dsa, sizeof(struct sockaddr_in) ) == -1)
   				{
   					close(sd);
   					toSrvMapErr(ZERO_IF, srv_type); // add to services
   					evdata.message = "Failed to bind: " + err2string( strerror(errno) );
   					evdata.type = SNM_GM_ERROR_BIND;
   					ei->onEvent(evdata);
   					return;
   				}
   				else
   				{
   					toSrvMap( ZERO_IF, srv_type, ref(srv) ); // add to services
   				}
   			}
   		}
   	}

	while(srv.run_flag)
	{
		l = recvfrom(sd, rbuffer, sizeof(rbuffer), 0, NULL, NULL);
		if(!srv.run_flag) break;
		if(l != -1)
		{
			srv.rbcount++;
			//cout << getLocalTime() << " Received server message: " << l << " from: " <<  inet_ntoa(psa.sin_addr) << endl;
			if( (dhcp_hdr->op == 2) and (dhcp_hdr->hlen == 6) and (dhcp_hdr->magic_cookie == magic_cookie) ) // packet error check
			{
				//cout << "ciaddr: " << inet_ntoa(dhcp_hdr->ciaddr) << " yiaddr: " << inet_ntoa(dhcp_hdr->yiaddr) << " OK" << endl;
				//cout << "MAC: " << macBtoS(dhcp_hdr->chaddr) << endl;
				offset = sizeof(dhcp_header);
				while(rbuffer[offset] != 255)
				{
					opt = rbuffer[offset++];
					len = rbuffer[offset++];
					if(len == 0) break; // options error check
					//cout << "Option: " << (int) opt << " " << (int) len << endl;
					if(opt == DHCP_OPT_MSSG_TYPE)
					{
						//cout << "Message type: " << (int) rbuffer[offset] << endl;
						if( srv.run_flag and (rbuffer[offset] == DHCPACK) ) // save data on positive acknowledgment only
						{
							if(dbm->toARProw( macBtoS(dhcp_hdr->chaddr).c_str(), inet_ntoa(dhcp_hdr->yiaddr) ) != SQLITE_OK)
							{
								srv.sqlerrc++;
							}
						}
						break;
					}
					offset += len;
					if( offset > sizeof(rbuffer) ) break; // options error check
				}
			}
		}
	}
	close(sd);
	onReturn(ZERO_IF, srv_type);
	return;
}
