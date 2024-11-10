//======================================================================================
// Name        : snmnetlib.hh
// Author      : Dmitry Komyagin
// Version     : 0.6
// Created on  : Nov 8, 2024
// Copyright   : Public domain
// Description : Header file for SNMONITOR networking library, Linux, ISO C++14
//======================================================================================

#ifndef SNMNETLIB_HH_
#define SNMNETLIB_HH_

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <iostream>
#include <net/if.h>
#include <netdb.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <linux/rtnetlink.h>
#include <string.h>

#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <map>
#include <regex>

#define IPV4_ALENGTH 4
#define PORT_ANY 0

#define HTONS(c) (uint16_t) ((((c) & 0xFF00) >> 8) | (((c) & 0x00FF) << 8))
#define NTOHS(c) (uint16_t) ((((c) & 0xFF00) >> 8) | (((c) & 0x00FF) << 8))
#define NBNS_ENCODE_H(b) (char) ('A' + ((b) >> 4))
#define NBNS_ENCODE_L(b) (char) ('A' + ((b) & 0x0F))

#define NAME_SERVICE_UDP_PORT 137
#define NAME_SERVICE_TCP_PORT 137
#define UCAST_REQ_RETRY_TIMEOUT 3 // in seconds
#define MCAST_REQ_RETRY_TIMEOUT 3 // in seconds

// Convert MAC address from char array to string
std::string macBtoS(unsigned char *mac);
// Convert MAC address from string to char array
unsigned char *macStoB(const char *mac_str);

// Interface
struct interface
{
	char if_name[IFNAMSIZ];
	uint32_t if_index;
	unsigned char mac_addr[ETH_ALEN];
	int mtu;
	in_addr   ip_addr;			// big-endian order
	in_addr   net_mask;			// big-endian order
	in_addr   net_addr;			// big-endian order
	in_addr   broadcast_addr; 	// big-endian order
	in_addr_t min_host;			// little-endian order
	in_addr_t max_host;			// little-endian order
	struct in6_addr sin6_addr;	// IPv6 link-local address
	uint32_t sin6_scope_id;		// IPv6 scope-id
};

// ARP

#define STD_ARP_PACKET_SIZE 60
#define ARP_BUFFER_SIZE STD_ARP_PACKET_SIZE
#define ARP_RETRANS_TIME 1	// Waiting time (in seconds) before retransmission
#define ARP_MCAST_SOLICIT 3
// RFC 826
#pragma pack(push,1)
struct arphdr_eth_ipv4
 {
	uint16_t ar_hrd;	// Hardware address space
	uint16_t ar_pro;	// Protocol address space
	uint8_t  ar_hln;	// Byte length of each hardware address
	uint8_t  ar_pln;	// Byte length of each protocol address
	uint16_t ar_op;		// Opcode (ares_op$REQUEST | ares_op$REPLY)
	unsigned char ar_sha[ETH_ALEN];	// Hardware address of sender
	in_addr_t ar_sip;				// Protocol address of sender
	unsigned char ar_tha[ETH_ALEN];	// Hardware address of target
	in_addr_t ar_tip;				// Protocol address of target
 };
#pragma pack(pop)

// UDP

struct udphdr
{
  uint16_t sport; 		// source port
  uint16_t dport; 		// destination port
  uint16_t len; 		// udp length
  uint16_t checksum;	// udp checksum
};
//
uint16_t udp4_checksum(struct iphdr *ipv4header);

// DNS

// Additional return codes
#define EAI_SELF      -200
#define EAI_UNCONFRMD -202
//
int getDNSv4HostNameFC(in_addr_t ip_addr, char* host_name, bool allow_synthtc_recrds = false, socklen_t host_name_len = NI_MAXHOST);

// NetBIOS Name Service

#define NETBIOS_NAME_LEN 16

// RFC 1002
struct nbns_packet_header
{
   	uint16_t name_trn_id;	// Transaction ID for Name Service Transaction
   	uint16_t flags;			// Opcode, nm_flags, rcode
   	uint16_t qdcount;		// Number of entries in the question section
   	uint16_t ancount;		// Number of resource records in the answer section
   	uint16_t nscount;		// Number of resource records in the authority section
   	uint16_t arcount;		// Number of resource records in the additional records section
};
//
union nbns_packet_flags
{
   	uint16_t flags;
   	struct
	{
   		uint16_t rcode:4;		// Result codes of request
    	uint16_t nm_flags:7;	// Flags for operation
    	uint16_t opcode:5;		// Packet type code
    } bitset;
};

#define NB_QTYPE		0x0020	// NetBIOS general Name Service Resource Record
#define NBSTAT_QTYPE	0x0021	// NetBIOS NODE STATUS Resource Record
#define IN_QCLASS		0x0001	// Internet class

#define STD_NBNS_NAME_LEN 0x20	// 32 octets
#define STD_NBNS_NAME_END 0x00

#define OPCODE_RESPONSE_FLAG 0b10000	// Response packet
#define NM_FLAGS_TC		// Truncation Flag

// NetBIOS '*' name
#define NB_DUMMY_NAME {STD_NBNS_NAME_LEN,				\
		0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, \
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, \
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, \
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, \
		STD_NBNS_NAME_END}
// Standard NBNS name query request structure
struct unicast_nbns_name_query_req
{
   	// header.name_trn_id MUST be changed to a unique int
   	struct nbns_packet_header header = {0, 0, HTONS(1), 0, 0, 0};
   	const char question_name[34] = NB_DUMMY_NAME;
   	uint16_t question_type  = HTONS(NBSTAT_QTYPE);	// Type of the request
   	uint16_t question_class = HTONS(IN_QCLASS);		// Class of the request
};
//
/*
struct broadcast_nbns_name_query_req
{
   	// header.name_trn_id MUST be changed to a unique int
   	struct nbns_packet_header header = {0, HTONS(0x0110), HTONS(1), 0, 0, 0};
   	const char question_name[34] = NB_DUMMY_NAME;
   	uint16_t question_type  = HTONS(NBSTAT_QTYPE);	// Type of the request
   	uint16_t question_class = HTONS(IN_QCLASS);		// Class of the request
};
*/
// Standard NBNS name query reply structure
#pragma pack(push,1)
struct std_nbns_name_staus_rpl
{
   	struct nbns_packet_header header;
   	const char rr_name[34];
   	uint16_t rr_type;	// Resource record type code
   	uint16_t rr_class;	// Resource record class code
   	uint32_t ttl;		// Time To Live of a the resource record's name
   	uint16_t rdlength;	// Number of bytes in the RDATA field
   	uint8_t  num_names;	// Number of names
};
#pragma pack(pop)
//
struct nbns_node_name_entry
{
	char node_name[NETBIOS_NAME_LEN];	// Node name
	uint16_t name_flags;				// Name flags
};
// Name flags
# define GROUP_NAME_FLAG 0x8000 // Group name flag
//
#define NBDGM_TYPE_DIRECT_UNIQUE_DGM  0x10
#define NBDGM_TYPE_DIRECT_GROUP_DGM   0x11
#define NBDGM_TYPE_BROADCAST_DGM      0x12
#define NBDGM_TYPE_DATAGRAM_ERROR     0x13
#define NBDGM_TYPE_DATAGRAM_QUERY_REQ 0x14
#define NBDGM_TYPE_DATAGRAM_POS_RESPS 0x15
#define NBDGM_TYPE_DATAGRAM_NEG_RESPS 0x16
//
#pragma pack(push,1)
struct nbdgm_header
{
	uint8_t  msg_type; 		// Message type
	struct {
		uint8_t m:1;		// MORE flag, If set then more NetBIOS datagram fragments follow.
		uint8_t f:1;		// FIRST packet flag
		uint8_t snt:2;		// Source End-Node type (00 = B node, 01 = P node, 10 = M node, 11 = NBDD)
		uint8_t rsrvd:4; 	// Reserved, must be zero
	} flags; 				// Flags
	uint16_t dgm_id; 		// Datagram ID
	uint32_t source_ip;		// Source IP
	uint16_t source_port;	// Source port
	uint16_t dgm_length;	// Datagram length
	uint16_t pkt_offset;	// Datagram length
};
#pragma pack(pop)

//
char decode_node_name(char *node_name, char *host_name);
// NetBIOS name types
std::string getNBNameType(uint8_t type);
//
// Note: Standard 16-bytes name only!
std::tuple<std::string, uint8_t, uint8_t> decode_nbns_name_16(char *buffer);
//
// Note: Just for testing
std::string _encode_nbns_name_16(std::string name, char type = '\0');
// SMB protocol header
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/69a29f73-de0c-45a6-a1aa-8ceeea42217f
#pragma pack(push,1)
struct smb_header
{
	uint8_t   protocol[4]; 			// Protocol (this field MUST contain the 4-byte literal string '\xFF', 'S', 'M', 'B')
	uint8_t   command; 				// Command
	uint8_t   err_class;			// Error class
	uint8_t   err_resrvd;			// Reserved
	uint16_t  err_code; 			// Error code
	uint8_t   flags;				// Flags
	uint16_t  flags2;				// Flags 2
	uint16_t  PIDHigh;				// High-order bytes of a process identifier (PID)
	uint8_t   SecurityFeatures[8];	// This 8-byte field has three possible interpretations
	uint16_t  resrvd;				// Reserved and SHOULD be set to 0x0000
	uint16_t  TID;					// Tree identifier (TID)
	uint16_t  PIDLow;				// The lower 16-bits of the PID
	uint16_t  UID;					// User identifier (UID)
	uint16_t  MID; 					// Multiplex identifier (MID)
};
#pragma pack(pop)
// SMB MailSlot protocol header
// https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-MAIL/[MS-MAIL].pdf
#pragma pack(push,1)
struct smb_mailslot_header
{
	uint8_t  WordCount; // MUST be set to 0x11 (17 words)
	struct {
		// SMB parameters block
	    uint16_t TotalParameterCount;
	    uint16_t TotalDataCount;
	    uint16_t MaxParameterCount;
	    uint16_t MaxDataCount;
	    uint8_t  MaxSetupCount;
	    uint8_t  Reserved1;
	    uint16_t Flags;
	    uint32_t Timeout;
	    uint16_t Reserved2;
	    uint16_t ParameterCount;
	    uint16_t ParameterOffset;
	    uint16_t DataCount;
	    uint16_t DataOffset;
	    uint8_t  SetupCount; 		// MUST be set to 0x03
	    uint8_t  Reserved3;
	    // SMB MailSlot header (SMB Setup block - 3 words)
	    uint16_t MailSlotOpcode; 	// MUST be set to 0x0001
	    uint16_t Priority; 			// The Priority field MUST be in the range of 0 through 9
	    uint16_t Class; 			// Class of the mailslot request (0x0001 -reliable; 0x0002 - unreliable, e.g. broadcasts)
	    // (SMB Data block)
	    uint16_t ByteCount; 		// MUST specify the number of bytes that follow this field
	    uint8_t  MailslotName[];	// A null-terminated, case-insensitive ASCII string, MUST be of the form "\mailslot\<name>"
//	    uint8_t  Padding[]: Padding data. The Padding field MUST be large enough so that the DataBytes
//	    field is 32-bit aligned. To that end, this field MUST be 0 through 3 bytes long, inclusive.
    } Words;
};
#pragma pack(pop)
// HostAnnouncement Browser Frame (0x01)
// DomainAnnouncement Browser Frame (0x0C)
// LocalMasterAnnouncement Browser Frame (0x0F)
#pragma pack(push,1)
struct annt_browser_frame
{
	uint8_t  Command; 				// MUST be 0x01 or 0x0C or 0x0F to use this frame structure
	uint8_t  UpdateCount; 			// MUST be sent as 0x00
	uint32_t Periodicity; 			// Announcement frequency of the server in milliseconds
	uint8_t  ServerName[16]; 		// MUST be a null-terminated ASCII server name with a length of 16 bytes, including the null terminator
	uint8_t  OSVersionMajor; 		// Server OS major version number
	uint8_t  OSVersionMinor; 		// Server OS minor version number
	uint32_t ServerType; 			//
	uint8_t  BrowserVersionMajor; 	// Major version number of the CIFS Browser Protocol, MUST be set this to 0x0F
	uint8_t  BrowserVersionMinor; 	// Minor version number of the CIFS Browser Protocol, MUST be set this to 0x01
	uint16_t Signature; 			// MUST be set to 0xAA55
	uint8_t  FrameEnding[];			// For HostAnnouncement, LocalMasterAnnouncement - Comment: optional null-terminated ASCII string
									// that MUST be less than or equal to 43 bytes including the null terminator
									// For DomainAnnouncement - LocalMasterBrowserName : null-terminated ASCII string
									// that MUST contain the name of the sender
};
#pragma pack(pop)
// Microsoft server types
#define SV_TYPE_WORKSTATION 0x00000001 // A server running the WorkStation Service
#define SV_TYPE_SERVER 0x00000002 // A server running the Server Service
#define SV_TYPE_SQLSERVER 0x00000004 // Any server running with SQL Server
#define SV_TYPE_DOMAIN_CTRL 0x00000008 // Primary domain controller
#define SV_TYPE_DOMAIN_BAKCTRL 0x00000010 // Backup domain controller
#define SV_TYPE_TIME_SOURCE 0x00000020 // Server is available as a time source for network time synchronization
#define SV_TYPE_AFP 0x00000040 // Apple File Protocol server
#define SV_TYPE_NOVELL 0x00000080 // Novell server
#define SV_TYPE_DOMAIN_MEMBER 0x00000100 // LAN Manager 2.x domain member
#define SV_TYPE_PRINTQ_SERVER 0x00000200 // Server sharing print queue
#define SV_TYPE_DIALIN_SERVER 0x00000400 // Server running dial-in service
#define SV_TYPE_SERVER_UNIX 0x00000800 // Unix or Xenix server
#define SV_TYPE_NT 0x00001000 // Windows NT operating system, Windows 2000 operating system, Windows XP operating system, Windows Server 2003 operating system, Windows Vista operating system, Windows 7 operating system,  Windows 8 operating system, Windows Server 2008 operating system, Windows Server 2008 R2 operating system, or Windows Server 2012 operating system
#define SV_TYPE_WFW 0x00002000 // Server running Windows for Workgroups
#define SV_TYPE_SERVER_MFPN 0x00004000 // Microsoft File and Print for NetWare
#define SV_TYPE_SERVER_NT 0x00008000 // Windows 2000 Server operating system, Windows Server 2003, or a server that is not a domain controller
#define SV_TYPE_POTENTIAL_BROWSER 0x00010000 // Server that can run the browser service
#define SV_TYPE_BACKUP_BROWSER 0x00020000 // Server running a browser service as backup
#define SV_TYPE_MASTER_BROWSER 0x00040000 // Server running the master browser service
#define SV_TYPE_DOMAIN_MASTER 0x00080000 // Server running the domain master browser
#define SV_TYPE_WINDOWS 0x00400000 // Windows 95 operating system, Windows 98 operating system, or Windows Millennium Edition operating system
#define SV_TYPE_DFS 0x00800000 // Root of a DFS tree
#define SV_TYPE_CLUSTER_NT 0x01000000 // Server clusters available in the domain
#define SV_TYPE_TERMINALSERVER 0x02000000 // Terminal server
#define SV_TYPE_CLUSTER_VS_NT 0x04000000 // Cluster virtual servers available in the domain
#define SV_TYPE_DCE 0x10000000 // IBM DSS (Directory and Security Services) or equivalent
#define SV_TYPE_ALTERNATE_XPORT 0x20000000 // Return list for alternate transport
#define SV_TYPE_LOCAL_LIST_ONLY 0x40000000 // Servers maintained by the browser
#define SV_TYPE_DOMAIN_ENUM 0x80000000 // Primary domain
#define SV_TYPE_ALL 0xFFFFFFFF // Return all of the servers mentioned previously
// Returns string of comma delimited names
std::string getMicrosoftServerTypeNames(uint32_t ServerType);

// mDNS

//
#define INADDR_MDNS_LOCAL_GROUP  ((in_addr_t) 0xe00000fb) 	// 224.0.0.251
#define MDNS_LOCAL_GROUP 0xfb0000e0 						// 224.0.0.251 little-endian order
#define MDNS_PORT 5353			// mDNS port
#define DNS_TYPE_A     1		// Host address
#define DNS_TYPE_PTR  12 		// Domain name pointer
#define DNS_TYPE_TXT  16 		// Text strings
#define DNS_TYPE_SRV  33 		// Server selection
#define DNS_TYPE_AAAA 28		// IPv6 address
#define DNS_TYPE_NSEC 47		// NSEC
#define DNS_CLASS_IN 1			// The Internet
#define DNS_CLASS_ALL 255		// Request for all records
#define DNS_RR_PTR_FLAG 0xC0 	// Presence of a pointer to a prior occurrence of the same name
#define MDNS_QU_FLAG 0x8000		// mDNS unicast-response bit in the class field
#define MDNSV6_LOCAL_GROUP "FF02:0:0:0:0:0:0:FB"
//
#pragma pack(push,1)
struct dns_packet_header
{
   	uint16_t name_trn_id;	// Transaction ID for Name Service Transaction
   	uint16_t flags;			// Flags
   	uint16_t qdcount;		// Number of entries in the question section
   	uint16_t ancount;		// Number of resource records in the answer section
   	uint16_t nscount;		// Number of resource records in the authority section
   	uint16_t arcount;		// Number of resource records in the additional records section
};
#pragma pack(pop)
//
struct dns_query_tail
{
   	uint16_t qtype;  	// Type of the request
   	uint16_t qlass; 	// Class of the request
};
//
#pragma pack(push,1)
struct dns_rr_tail
{
	uint16_t rrtype;  	// RR type codes
	uint16_t rrlass; 	// Class of the data
	uint32_t ttl;		// TTL in seconds
	uint16_t rdlenth;	// Length in octets of the RDATA field
};
#pragma pack(pop)
//
union dns_rr_pointer
{
	uint16_t pointer;		// pointer
	union {
		uint16_t flag:2; 	// 0b11 by default
		uint16_t offset:14;	// offset
	} bitset;
};
//
union dns_flags  // little-endian order
{
	uint16_t flags;
	struct {
		uint16_t rcode:4;	// Response code
		uint16_t nathd:1;	// Non-authenticated data
		uint16_t aath:1;	// Answer authenticated
		uint16_t z:1;		// Zero bit (reserved)
		uint16_t ra:1;		// Recursion available
		uint16_t rd:1;		// Recursion desired
		uint16_t tc:1;		// Truncation flag
		uint16_t aa:1;		// Authoritative answer flag
		uint16_t opcode:4;	// Operation code
		uint16_t qr:1; 		// Query/Response flag
	} bitset;
};
//
std::string encode_mdns_name(std::string name);
//
// Note: Just for testing
std::string _decode_mdns_name(const char *enc_name);
// Return number of bytes has been written to buffer
short int make_simple_mdns_request(std::string  name, void *buffer);
//
std::string get_mdns_rr_name(char *buffer, uint16_t offset, uint16_t mssg_offset = 0);
//
unsigned short mdns_rr_name_len(char *buffer, unsigned short offset);
//
std::string arpa_ip4_string(in_addr_t addr, bool ending_dot = false);
//
std::string arpa_ip6_string(in6_addr addr, bool ending_dot = false);

//
#define SSDP_SEARCH_MESSAGE "M-SEARCH * HTTP/1.1\r\n"
#define INADDR_SSDP_LOCAL_GROUP ((in_addr_t) 0xeffffffa)
#define SSDP_MULTICAST_PORT     ((in_port_t) 1900)
#define UPNP_TCP_UCAST_REQ_RETRY_TIMEOUT 5	//should be 30 seconds by default
#define UPNP_TCP_REPLY_BUFFER_SIZE 10000

//
struct uri_data
{
	std::string host;
	std::string port;
	std::string path;
};
//
struct upnp_device_info
{
	std::string friendlyName;
	std::string manufacturer;
	std::string modelDescription;
};
//
std::string getLocationUrl(char *buffer);
//
struct uri_data *parseURL(std::string url);
//
bool checkHTTPStatusCode(std::string buffer);
//
struct upnp_device_info *getXMLInfo(std::string xml_buffer);
//
//upnp_device_info *getUPnPDeviceInfo(struct uri_data *uri, in_addr_t if_ipv4_addr);

// LLDP

// IEEE Std 802.1AB
// 01:80:c2:00:00:0e or 01:80:c2:00:00:03 or 01:80:c2:00:00:00, ethernet type — 0x88cc
#define ETH_P_LLDP	0x88CC

// DHCP

// RFC 951, RFC 3456, RFC 2132

#define MAGIC_COOKIE 0x63825363

// DHCP Message types
#define DHCPDISCOVER 	1
#define DHCPOFFER 		2
#define DHCPREQUEST		3
#define DHCPDECLINE		4
#define DHCPACK 		5
#define DHCPNAK 		6
#define DHCPRELEASE 	7
#define DHCPINFORM 		8

// DHCP Message options
#define DHCP_OPT_HOST_NAME 		12
#define DHCP_OPT_MSSG_TYPE 		53
#define DHCP_OPT_PARAM_REQ_LST 	55
#define DHCP_OPT_VNDR_CLASS_ID 	60

struct dhcp_header
{
	uint8_t  op;			// packet type
	uint8_t  htype;			// hardware address type
	uint8_t  hlen;			// hardware address length
	uint8_t  hops;			// hops
	uint32_t xid;			// random transaction id number
	uint16_t secs;			// seconds used in timing
	uint16_t flags;			// flags
	in_addr ciaddr;			// client IP address
	in_addr yiaddr;			// 'your' (client) IP address; filled by server if client doesn't know its own address (ciaddr was 0)
    in_addr siaddr;			// server IP address; returned in bootreply by server
    in_addr giaddr;			// gateway IP address, used in optional cross-gateway booting
    uint8_t chaddr[16];		// client hardware address, filled in by client
    char sname[64];			// optional server host name, null terminated string
    char file[128];			// boot file name, null terminated string; 'generic' name or null in bootrequest,
    						// fully qualified directory-path name in bootreply
    uint32_t magic_cookie;	// As suggested in RFC-951 0x63825363
};

//LLMNR

// RFC 4795
#define LLMNR_LOCAL_GROUP 0xfc0000e0 // 224.0.0.252 little-endian order
#define LLMNR_PORT 5355 // LLMNR port
//
union llmnr_flags  // little-endian order
{
	uint16_t flags;
	struct {
		uint16_t rcode:4;	// Response code
		uint16_t z:4;		// Zero bits (reserved)
		uint16_t t:1;		// Tentative
		uint16_t tc:1;		// Truncation flag
		uint16_t c:1;		// Conflict flag
		uint16_t opcode:4;	// Operation code
		uint16_t qr:1; 		// Query/Response flag
	} bitset;
};

// ICMPv6

#define udp6_checksum icmpv6_checksum
//
struct icmpv6_hdr
{
	uint8_t  type;
	uint8_t  code;
	uint16_t checksum;
};
//
struct icmpv6_type_133 // Router solicitation
{
	uint32_t         reserved;
	uint8_t          type;
	uint8_t          len; 		// 1 means  8 bites
	uint8_t          lladdr[]; 	// link-layer address
};
//
struct icmpv6_type_135 // Neighbor solicitation
{
	uint32_t         reserved;
	struct	in6_addr taddr; 	// target address
};
//
struct icmpv6_type_136 // Neighbor advertisement
{
	uint32_t         flags;
	struct	in6_addr taddr; 	// target address
	uint8_t          type;		// type of option
	uint8_t          len; 		// length in bytes
	uint8_t          lladdr[]; 	// link-layer address
};
//
uint16_t icmpv6_checksum(struct ip6_hdr *ipv6header);

#endif /* SNMNETLIB_HH_ */
