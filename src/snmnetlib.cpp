//======================================================================================
// Name        : snmnetlib.cpp
// Author      : Dmitry Komyagin
// Version     : 0.6
// Created on  : Nov 8, 2024
// Copyright   : Public domain
// Description : SNMONITOR networking library, Linux, ISO C++14
//======================================================================================

#include "snmnetlib.hh"

using namespace std;

// Convert MAC address from char array to string
string macBtoS(unsigned char *mac)
{
 	stringstream mstr;

	if(mac == nullptr) return string();

	mstr << hex << setfill('0')
		 << setw(2) << (int) mac[0] << ':'
		 << setw(2) << (int) mac[1] << ':'
		 << setw(2) << (int) mac[2] << ':'
		 << setw(2) << (int) mac[3] << ':'
		 << setw(2) << (int) mac[4] << ':'
		 << setw(2) << (int) mac[5];

	return mstr.str();
}
// Convert MAC address from string to char array
unsigned char *macStoB(const char *mac_str)
{
	unsigned char hb, lb, i;
	static __thread unsigned char mac[ETH_ALEN];

	for(i = 0; i < ETH_ALEN; i++)
	{
		hb = int(mac_str[i*3]);
		hb = (hb < 58) ? (hb - 48) : (hb - 87);
		lb = int(mac_str[i*3 + 1]);
		lb = (lb < 58) ? (lb - 48) : (lb - 87);
		mac[i] = (hb << 4) | lb;
	}
	return mac;
}
// UDP
//
uint16_t udp4_checksum(struct iphdr *ipv4header)
{
	// RFC 768
	short count = 8 + NTOHS(ipv4header->tot_len); // source (4) + destination (4)
	uint16_t *addr = (uint16_t *) &ipv4header->saddr;
	// tot_len is the length of ip packet but udp length is 20 bytes less (0x1400 in network order)
	register int sum = (ipv4header->tot_len - 0x1400) + (uint16_t) (ipv4header->protocol << 8);

	while(count > 1)
	{
		//  This is the inner loop
		sum += *(addr++);
		count -= 2;
	}
	//  Add left-over byte, if any
	if(count > 0)
		sum += *addr;
	//  Fold 32-bit sum to 16 bits
	while(sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (uint16_t) ~sum;
}
// DNS
//
int getDNSv4HostNameFC(in_addr_t ip_addr, char* host_name, bool allow_synthtc_recrds, socklen_t host_name_len)
{
	int rc;
	const in_addr_t lh_ipv4 = 0x007f; // 127.0.x.y
	struct sockaddr_in sa = {0};
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = ip_addr;

	struct addrinfo *result, *rp;
	struct sockaddr_in *psa;
	struct addrinfo hints = {0};
	hints.ai_family = AF_INET;
	hints.ai_protocol = IPPROTO_UDP;

	memset( host_name, 0, sizeof(host_name_len) );
	rc = getnameinfo( (struct sockaddr *) &sa, sizeof(struct sockaddr), host_name, host_name_len, NULL, 0, NI_NAMEREQD );
	if(rc == 0)
	{
		if(!allow_synthtc_recrds)
		{
			if(strcmp(host_name, "_gateway") == 0)
			{
				memset( host_name, 0, sizeof(host_name_len) );
				return EAI_NONAME;
			}
		}
		rc = getaddrinfo(host_name, NULL, &hints, &result);
		if(rc == 0)
		{
			for(rp = result; rp != NULL; rp = rp->ai_next)
			{
				psa = (sockaddr_in *) rp->ai_addr;
			    if(psa->sin_addr.s_addr == sa.sin_addr.s_addr) // host name confirmed
			    {
			    	freeaddrinfo(result);
			    	return 0;
			    }
			    else if( (psa->sin_addr.s_addr & 0x00FF) == lh_ipv4 )
			    {
			    	freeaddrinfo(result);
			    	if(allow_synthtc_recrds)
			    	{
			    	   	return 0;
			    	}
			    	else
			    	{
			    		memset( host_name, 0, sizeof(host_name_len) );
			    		return EAI_SELF; // actually not an error
			    	}
			    }
			}
			freeaddrinfo(result);
			rc = EAI_UNCONFRMD; // host name not confirmed, error
		}
		memset( host_name, 0, sizeof(host_name_len) ); // if host name not confirmed or on error
	}
	return rc; // host name name not found or error
}
// NetBIOS Name Service
//
char decode_node_name(char *node_name, char *host_name)
{
	for(int i = 0; i < (NETBIOS_NAME_LEN - 1); ++i)
	{
		host_name[i] = (node_name[i] != 0x20) ? node_name[i] : '\0';
	}
	host_name[NETBIOS_NAME_LEN - 1] = '\0';

	return node_name[NETBIOS_NAME_LEN - 1];
}
// NetBIOS name types
string getNBNameType(uint8_t type)
{
	static const map<uint8_t, string> nb_name_type =
	{
		{0x00,	"Workstation"},
		{0x01,	"Master Browser"},	// MUST have name [01][02]__MSBROWSE__[02][01]
		{0x03,	"Messenger service/Main name"},
		{0x05,	"Forwarded name"},
		{0x06,	"RAS Server service"},
		{0x1b,	"Domain Master Browser"},
		{0x1c,	"Domain Controllers"},
		{0x1d,	"Local Master Browser"},
		{0x1e,	"Browser Election Service"},
		{0x1f,	"Net DDE Service"},
		{0x20,	"Server service"},
		{0x21,	"RAS client service"},
		{0x22,	"Exchange Interchange (MSMail Connector)"},
		{0x23,	"Exchange Store"},
		{0x24,	"Exchange Directory"},
		{0x2b,	"Lotus Notes Server service"},
		{0x30,	"Modem sharing server service"},
		{0x31,	"Modem sharing client service"},
		{0x43,	"SMS Clients Remote Control"},
		{0x44,	"SMS Administrators Remote Control Tool"},
		{0x45,	"SMS Clients Remote Chat"},
		{0x46,	"SMS Clients Remote Transfer"},
		{0x4c,	"DEC Pathworks TCP/IP Service on Windows NT"},
		{0x52,	"DEC Pathworks TCP/IP Service on Windows NT"},
		{0x6a,	"Microsoft Exchange IMC"},
		{0x87,	"Microsoft Exchange MTA"},
		{0xbe,	"Network Monitor Agent"},
		{0xbf,	"Network Monitor Analyzer"},
	};
	return nb_name_type.at(type);
}
//
// Note: Standard 16-bytes name only!
tuple<string, uint8_t, uint8_t> decode_nbns_name_16(char *buffer)
{
	string dname;
	char c;
	uint8_t type, i;

	for(i = 1; i < buffer[0] - 2 ; i += 2)
	{
		c = ( (buffer[i] - 'A') << 4 ) | (buffer[i + 1] -'A');
		if( c != ' ' ) dname += c;
	}
	type = ( (buffer[i] - 'A') << 4 ) | (buffer[i + 1] -'A');
	return {dname, type, buffer[0]};
}
//
// Note: Just for testing
string _encode_nbns_name_16(string name, char type)
{
	string ename;
	uint8_t l = 0;
	for(char c:name)
	{
		ename += NBNS_ENCODE_H(c);
	    ename += NBNS_ENCODE_L(c);
	    l += 1;
	}
	for( ; l < 15; ++l )
	{
		ename += NBNS_ENCODE_H(0x20);
	    ename += NBNS_ENCODE_L(0x20);
	}
	ename += NBNS_ENCODE_H(type);
	ename += NBNS_ENCODE_L(type);
	ename += '\0';
	ename = ((char) (l*2 + 2)) + ename;
	return ename;
}
// Returns string of comma delimited names
string getMicrosoftServerTypeNames(uint32_t ServerType)
{
	string names;
	static const map<uint32_t, string> SrvType =
	{
		{SV_TYPE_WORKSTATION, "Workstation"},
		{SV_TYPE_SERVER, "Server"},
		{SV_TYPE_SQLSERVER, "SQL Server"},
		{SV_TYPE_DOMAIN_CTRL, "Primary Domain Controller"},
		{SV_TYPE_DOMAIN_BAKCTRL, "Backup Domain Controller"},
		{SV_TYPE_TIME_SOURCE, "Time Server"},
		{SV_TYPE_AFP, "AFP Server"},
		{SV_TYPE_NOVELL, "Novell Server"},
		{SV_TYPE_DOMAIN_MEMBER, "LAN Manager"},
		{SV_TYPE_PRINTQ_SERVER, "Print Queue Server"},
		{SV_TYPE_DIALIN_SERVER, "DialIn Server"},
		{SV_TYPE_SERVER_UNIX, "Unix Server"},
		{SV_TYPE_NT, "NT Workstation"},
		{SV_TYPE_WFW, "WfW Host"},
		{SV_TYPE_SERVER_MFPN, "MFPN Server"},
		{SV_TYPE_SERVER_NT, "NT Server"},
		{SV_TYPE_WINDOWS, "Legacy Windows Workstation"},
		{SV_TYPE_DFS, "DFS Server"},
		{SV_TYPE_TERMINALSERVER, "Terminal Server"}
	};
	for(auto it: SrvType)
	{
		if( (it.first&ServerType) == it.first )
		{
			names += it.second + ", ";
		}
	}
	if( names.length() )
	{
		names.erase(names.size() - 2, 2); // remove ending ", "
	}
	return names;
}
// mDNS
//
string encode_mdns_name(string name)
{
	stringstream outstream(ios_base::in | ios_base::out | ios_base::binary);
	string chunk;

	stringstream InStream(name);

	while( getline(InStream, chunk, '.') )
	{
		outstream << char(chunk.size()) << chunk;
	}
	return outstream.str();
}
//
// Note: Just for testing
string _decode_mdns_name(const char *enc_name)
{
	unsigned short len, idx = 0;
	string name(enc_name);

	len = name[idx];

	while(len > 0) {
		idx += len + 1;
		len = name[idx];
		name[idx] = '.';
	}
	name.erase(0, 1);
	return name;
}
// Return number of bytes has been written to buffer
short int make_simple_mdns_request(string  name, void *buffer)
{
	struct dns_packet_header hdr = {0, 0, HTONS(1), 0, 0, 0};
	struct dns_query_tail tail = {HTONS(DNS_TYPE_PTR), HTONS(MDNS_QU_FLAG | DNS_CLASS_IN)};
	string encoded_name = encode_mdns_name(name);
	unsigned short int offset = sizeof(struct dns_packet_header);

	memcpy((char *) buffer, (char *) &hdr, sizeof(hdr));
	strcpy( (char *) buffer + offset, encoded_name.c_str() );
	offset += encoded_name.size();
	((char *) buffer)[offset++] = 0;	// name string termination
	memcpy( (char *) buffer + offset, (char *) &tail, sizeof(tail) );
	offset += sizeof(tail);

	return offset;
}
//
string get_mdns_rr_name(char *buffer, uint16_t offset, uint16_t mssg_offset)
{
	union dns_rr_pointer rr_ptr;
	uint8_t len;
	string domain_name;

	len = buffer[offset];
	while(len > 0)
	{
		if( (len & DNS_RR_PTR_FLAG) != DNS_RR_PTR_FLAG )
		{
			domain_name.append( (const char *) &buffer[offset + 1], len );
		    offset += len + 1;
		    len = buffer[offset];
		    if(len != 0) domain_name.append(".");
		}
		else
		{
			rr_ptr.pointer = ntohs(*((uint16_t *) &buffer[offset]));
			offset = rr_ptr.bitset.offset + mssg_offset;
			len = buffer[offset];
		}
	}
	return domain_name;
}
//
unsigned short mdns_rr_name_len(char *buffer, unsigned short offset)
{
	uint8_t len = buffer[offset];
	unsigned short start = offset;

	while(len > 0)
	{
		if( (len & DNS_RR_PTR_FLAG) != DNS_RR_PTR_FLAG )
		{
			// go to the next part of the name
			offset += len + 1;
			len = buffer[offset];
		}
		else
		{
			// pointer detected
			++offset;
			break;
		}
	}
	return (offset - start + 1);
}
//
string arpa_ip4_string(in_addr_t addr, bool ending_dot)
{
	stringstream  arpa;
	union
	{
		in_addr_t ipv4_addr;
		unsigned char byte[4];
	} byteset;

	byteset.ipv4_addr = addr;

	arpa << (int) byteset.byte[3] << "." << (int) byteset.byte[2] << "." \
		 << (int) byteset.byte[1] << "." << (int) byteset.byte[0] << ".in-addr.arpa";
	if(ending_dot) arpa << ".";
	return arpa.str();
}
//
string arpa_ip6_string(in6_addr addr, bool ending_dot)
{
	stringstream  arpa;
	uint8_t b;

	arpa << hex << uppercase;
	for(short i = 15; i >= 0 ; --i)
	{
		b = addr.__in6_u.__u6_addr8[i];
		arpa << (int) (b & 0xf) << "." << (int) (b >> 4) << ".";
	}
	arpa << "ip6.arpa";
	if(ending_dot) arpa << ".";
	return arpa.str();
}

// UPnP

//
string getLocationUrl(char *buffer)
{
	string location_url = string(buffer);
	const char *location_str = "LOCATION:";
	regex pattern(location_str, regex_constants::icase);
	smatch m;

	if(regex_search(location_url, m, pattern) != true)
		return string();
	auto bpos = m.position();
	bpos += strlen(location_str);
	auto epos = location_url.find("\r\n", bpos);
	if(epos == string::npos)
		return string();

	location_url = location_url.substr(bpos, epos - bpos);
	location_url.erase( remove(location_url.begin(), location_url.end(), ' '), location_url.end() );

	return location_url;
}
//
struct uri_data *parseURL(string url)
{
	static __thread struct uri_data data;

	auto b_addr = url.find("://");
	if(b_addr == string::npos)
		return nullptr;
	b_addr += 3;
	auto e_addr = url.find(":", b_addr);
	if(e_addr == string::npos)
		return nullptr;
	auto b_port = e_addr + 1;
	auto e_port = url.find("/", b_port);
	if(e_port == string::npos)
		return nullptr;
	data.host = url.substr(b_addr, e_addr - b_addr);
	data.port = url.substr(b_port, e_port - b_port);
	data.path = url.substr(e_port);

	return &data;
}
//
bool checkHTTPStatusCode(string buffer)
{
	return regex_match( buffer, regex("HTTP/[1-9](\\.)?[0-9]? 200 OK\r\n((.|\\s)*?)", regex_constants::icase) );
	// ((.|\\s)*?)lazy search
}
//
struct upnp_device_info *getXMLInfo(string xml_buffer)
{
	static __thread struct upnp_device_info xml_data;
	const char fn_str[] = "<friendlyName>";
	const char mf_str[] = "<manufacturer>";
	const char md_str[] = "<modelDescription>";

	{
		auto bpos = xml_buffer.find(fn_str);
		if(bpos != string::npos)
		{
			bpos += strlen(fn_str);
			auto epos = xml_buffer.find("<", bpos);
			if(epos != string::npos)
			{
				xml_data.friendlyName = xml_buffer.substr(bpos, epos - bpos);
			}

		}
	}
	{
		auto bpos = xml_buffer.find(mf_str);
		if(bpos != string::npos)
		{
			bpos += strlen(mf_str);
			auto epos = xml_buffer.find("<", bpos);
			if(epos != string::npos)
			{
				xml_data.manufacturer = xml_buffer.substr(bpos, epos - bpos);
			}

		}
	}
	{
		auto bpos = xml_buffer.find(md_str);
		if(bpos != string::npos)
		{
			bpos += strlen(md_str);
			auto epos = xml_buffer.find("<", bpos);
			if(epos != string::npos)
			{
				xml_data.modelDescription = xml_buffer.substr(bpos, epos - bpos);
			}

		}
	}
	return &xml_data;
}

// ICMPv6

//
uint16_t icmpv6_checksum(struct ip6_hdr *ipv6header)
{
    // RFC 1071
    short count = 32 + NTOHS(ipv6header->ip6_ctlun.ip6_un1.ip6_un1_plen); // source (16) + destination (16)
    uint16_t *addr = (uint16_t *) &ipv6header->ip6_src;
    register int sum = ipv6header->ip6_ctlun.ip6_un1.ip6_un1_plen + (uint16_t) (ipv6header->ip6_ctlun.ip6_un1.ip6_un1_nxt << 8);

    while(count > 1)
    {
        //  This is the inner loop
        sum += *(addr++);
        count -= 2;
    }
    //  Add left-over byte, if any
    if(count > 0)
        sum += *addr;
    //  Fold 32-bit sum to 16 bits
    while(sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t) ~sum;
}
