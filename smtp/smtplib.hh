//======================================================================================
// Name        : smtplib.hh
// Author      : Dmitry Komyagin
// Version     : 1.1
// Created on  : Nov 8, 2024
// Copyright   : Public domain
// Description : Header file for SMTP embedded client library, Linux, ISO C++14
//======================================================================================

/*************************************************************************************************
 * THIRD-PARTY SOFTWARE NOTE
 *
 * The following software might be used in this product:
 *
 * OpenSSL Library, http://openssl-library.org/
 * Read THIRD-PARTY-LICENSES.txt or visit: http://openssl-library.org/source/license/index.html
 *************************************************************************************************/

#ifndef SMTPLIB_HH_
#define SMTPLIB_HH_

// Comment next line to disable TLS/SSL support
#define _ENABLE_TLS_SSL_

#include <iostream>
#include <vector>

#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <poll.h>
#include <limits.h>
#include <unistd.h>

#include <set>
#include <regex>
#include <mutex>
#include <condition_variable>
#include <iomanip>
#include <thread>
#include <atomic>
#include <queue>
#include <csignal>
#include <chrono>

#ifdef _ENABLE_TLS_SSL_
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#endif // _ENABLE_TLS_SSL_

#include "base64.hh"
#include "eventinf.hh"

#ifdef _ENABLE_TLS_SSL_
    #define SMTPLIB_BUILD_TLS_SUPPORTED true
    #define SMTP_CONNECTION_CLASS class smtpConnection_TLS
#else
    #define SMTPLIB_BUILD_TLS_SUPPORTED false
    #define SMTP_CONNECTION_CLASS class smtpConnection
#endif // _ENABLE_TLS_SSL_

using namespace std::chrono_literals;

#define SMTP_CLIENT_NAME "KDJ Embedded SMTP Client"

#define SMTP_BUF_SZ 	1025 // 1024 + 1
#define SMTP_SSL_BUF_SZ 4097 // 4096 + 1
#define SMTPS_PORT 465

#define SSL_CERT_DEFAULT_DIR "/etc/ssl/certs/"

#define SMTP_REQ_RETRY_TIMEOUT 5 //should be 30 seconds by default
#define SMTP_TCP_CONNECT_TIMEOUT 10000 // in milliseconds

// RFC 5321
#define SMTP_SERVICE_READY		220 // Service ready
#define SMTP_CODE_OK 			250 // Requested mail action okay, completed
#define SMTP_CODE_OK_FWD		251 // User not local; will forward
#define SMTP_CODE_START_MAIL	354 // Start mail input
#define SMTP_CODE_NO_SERVICE 	421 // Service not available, closing transmission channel
#define SMTP_CODE_AUTH_FAILURE	454 // Temporary authentication failure
#define SMTP_CODE_SYNTAX_ERR	501 // Syntax error in parameters or arguments
#define SMTP_CODE_NOT_IMPLMTD 	502 // Command not implemented
#define SMTP_CODE_NO_MAIL	 	521 // <domain> does not accept mail RFC 1846
#define SMTP_CODE_NO_MAILBOX 	550 // Requested action not taken: mailbox unavailable
#define SMTP_CODE_FWD_ERR	 	551 // The recipient is not local to the server - relay denied
#define SMTP_CODE_NOT_ALLOWED	553 // Requested action not taken: mailbox name not allowed
#define SMTP_CODE_NO_SMTP 		554 // Transaction failed (Or, in the case of a connection-opening response, "No SMTP service here")
#define SMTP_CODE_NOT_ACCEPTED	554 // Address not accepted (many different reasons)
#define SMTP_CODE_PARAM_ERR		555 // MAIL FROM/RCPT TO parameters not recognized or not implemented
//RFC  4954
#define SMTP_CODE_AUTH_OK 		235 // 2.7.0  Authentication succeeded
#define SMTP_CODE_SRV_CHALLNGE 	334 // Server challenge - the text part contains the Base64-encoded challenge
#define SMTP_CODE_AUTH_FAILED 	535 // 5.7.8 Authentication credentials invalid

// Open connection return codes
#define SMTP_OC_OK 			  0
#define SMTP_OC_SSL_OK        0
#define SMTP_OC_SETUP_ERR	-11 //
#define SMTP_OC_SOCKET_ERR 	-12 // Unable to open socket
#define SMTP_OC_CONN_ERR 	-13 // Connection error
#define SMTP_OC_TLS_SYS_ERR	-14 // SSL/TLS system error
#define SMTP_OC_TLS_CON_ERR	-15 // SSL/TLS connection error
#define SMTP_OC_TLS_VRF_ERR	-16 // SSL certificate problem
#define SMTP_OC_AUTH_M_ERR 	-17 // No common authentication method
#define SMTP_OC_AUTH_C_ERR 	-18 // Authentication credentials invalid

#define SMTP_TCP_READ_ERR 	-1
#define SMTP_TCP_SEND_ERR	-2

#define SMTP_TLS_SSL_READ_ERR 	-1
#define SMTP_TLS_SSL_SEND_ERR 	-2

// Send mail return codes
#define SEND_MAIL_OK		 	0
#define SEND_MAIL_SETUP_ERR 	SMTP_OC_SETUP_ERR
#define SEND_MAIL_SOCKET_ERR 	SMTP_OC_SOCKET_ERR
#define SEND_MAIL_CONN_ERR 		SMTP_OC_CONN_ERR
#define SEND_MAIL_TLS_SYS_ERR 	SMTP_OC_TLS_SYS_ERR
#define SEND_MAIL_TLS_CON_ERR 	SMTP_OC_TLS_CON_ERR
#define SEND_MAIL_TLS_VRF_ERR 	SMTP_OC_TLS_VRF_ERR
#define SEND_MAIL_AUTH_C_ERR	SMTP_OC_AUTH_C_ERR
#define SEND_MAIL_AUTH_M_ERR	SMTP_OC_AUTH_M_ERR
#define SEND_MAIL_SEND_ERR		-101

// Retry default values
#define MAILER_SETUP_RETRY_TIME_LIMIT   72h // time
#define MAILER_OPEN_SOCKET_RETRY_LIMIT	  3 // count
#define MAILER_CONNECT_RETRY_TIME_LIMIT 72h // time
#define MAILER_TLS_SYS_RETRY_LIMIT		  3 // count
#define MAILER_TLS_CON_RETRY_LIMIT		 10 // count
#define MAILER_TLS_VRF_RETRY_LIMIT		  1 // count
#define MAILER_AUTH_M_RETRY_LIMIT		  1 // count
#define MAILER_AUTH_C_RETRY_LIMIT		  1 // count
#define MAILER_SEND_RETRY_TIME_LIMIT    24h // time
#define MAILER_MAIL_MAX_DEFFERED_QUEUE_LIFETIME 3600 // time in seconds

//
#define SEND_MAIL_ACT_SENT 0
#define SEND_MAIL_ACT_DROP 1
#define SEND_MAIL_ACT_WAIT 2
#define SEND_MAIL_ACT_RJCT 3

// Mail sender
#define MAIL_SENDER_CONNECTION_TIME     10 // in seconds

// Mail handler
#define MAIL_HANDLER_IDLE_TIME         600s
#define MAIL_HANDLER_BASE_RETRY_TIME     5s

//
using steady_time_point_t = std::chrono::time_point<std::chrono::steady_clock>;
using seconds = std::chrono::seconds;
//
struct smtpStats
{
	std::atomic<uint32_t> sent_cnt     = {0};
	std::atomic<uint32_t> conn_err_cnt = {0};
	std::atomic<uint32_t> drp_mail_cnt = {0};
};
//
struct smtpErrCount
{
	std::atomic<uint16_t> setup_err		= {0};
	std::atomic<uint8_t>  socket_err	= {0};
	std::atomic<uint16_t> oc_err		= {0};
	std::atomic<uint16_t> tls_sys_err   = {0};
	std::atomic<uint16_t> tls_con_err   = {0};
	std::atomic<uint8_t>  tls_vrf_err	= {0};
	std::atomic<uint8_t>  auth_m_err 	= {0};
	std::atomic<uint8_t>  auth_c_err 	= {0};
	std::atomic<uint16_t> send_err		= {0};
	void clear();
};
//
struct smtpRetryLimits
{
    seconds setup_tw   	= MAILER_SETUP_RETRY_TIME_LIMIT;
	uint8_t socket  	= MAILER_OPEN_SOCKET_RETRY_LIMIT;
	seconds connect_tw  = MAILER_CONNECT_RETRY_TIME_LIMIT;
	uint8_t	tls_sys	    = MAILER_TLS_SYS_RETRY_LIMIT;
	uint8_t tls_con	    = MAILER_TLS_CON_RETRY_LIMIT;
	uint8_t tls_vrf	    = MAILER_TLS_VRF_RETRY_LIMIT;
	uint8_t auth_m    	= MAILER_AUTH_M_RETRY_LIMIT;
	uint8_t auth_c    	= MAILER_AUTH_C_RETRY_LIMIT;
	seconds send_tw   	= MAILER_SEND_RETRY_TIME_LIMIT;
	time_t  resend_tw 	= MAILER_MAIL_MAX_DEFFERED_QUEUE_LIFETIME;
};
//
struct postcard
{
	std::string from;
	std::vector<std::string> to;
	std::string subj;
	std::string message;
	char type;
	time_t timestamp;
};
//
struct smtpParams
{
	std::string srv = "";
	std::string port = "";
	std::string sndr = "";
	std::string rcpts = "";
	bool tls = false;
	std::string username = "";
	std::string password = "";
	bool verify = true;
	bool test = false;
};

// Class 'smtpEventInformer' definition
class smtpEventInformer: public eventInformer
{
    void onEvent(const eventData &info) override;
};

#ifdef _ENABLE_TLS_SSL_
// Class 'smtpTLS_SSL' definition
class smtpTLS_SSL
{
private:
	SSL_CTX *ctx = nullptr;
	SSL *ssl = nullptr;
	bool fatal_ssl_err = false, cverify = false, pverify = false;
	std::string peer_name;
	uint8_t _verbose_flags;
	eventInformer *_ei;
protected:
	std::string last_tls_mssg;
	std::set<std::string> ehlo_keywords;
	std::set<std::string> auth_methods;
	bool _tls_open = false;
protected:
	// Constructor
	smtpTLS_SSL(uint8_t verbose, eventInformer *eventInf);
	// Destructor
	virtual ~smtpTLS_SSL();
	// Reads SMTP server reply, returns return code or error code
	int readSrvResponse(bool on_closing = false);
	// Opens TLS/SSL connection, returns SMTP_OC_* code
	int connectSSL(const int socket);
	// Outputs server certificates to console
	void coutSrvCerts() const;
	// Sends SMTP command, returns response or error code
	int sendCmd_tls(std::string mssg, bool eod = false);
	// Sends EHLO command, returns response or error code
	int sendEHLO_tls(const std::string& hostName);
	// Sends QUIT command, closes TLS/SSL connection and socket, returns response or error code
	int sendQUIT_tls();
	// Properly closes TLS/SSL connection
	int closeSSL(bool sendQuit);
	// Aborts TLS/SSL connection
	void abortSSL();
	// Authentication, returns the last SMTP return code or error code
	// Only PLAIN and LOGIN authentication methods are supported
	int Authenticate(const std::string& username, const std::string& password);
	// Set verification for SMTP server
	void setVerification(bool certVerification, const std::string hostName);
	// Callback function on TLS/SSL error
	virtual void onTLSerror(int rc, std::string error_string) {};
};
#endif // _ENABLE_TLS_SSL_

// Class 'smtpConnection' definition
class smtpConnection
{
protected:
	struct smtpParams smtp_data;
	int sd = 0;
	std::string host_name, _username, _password;
	std::string last_err_mssg;
	struct addrinfo  *smtp_ai = nullptr;
	std::set<std::string> ehlo_keywords;
	bool setup = false, _std_open = false, auth = false, fatal_conn_err = false;
	uint8_t verbose_flags;
	class eventInformer *ei;
public:
	// Constructor
	smtpConnection(const struct smtpParams smtpData, uint8_t verbose, eventInformer *eventInf);
	// Destructor
	~smtpConnection();
protected:
	// Opens socket and returns socket descriptor on success; on error, -1 is returned
	int openSocket();
	// Connection environment setup. On success returns 0; on error, -1 is returned
	int setupConnection();
	// Sends SMTP command, returns response or error code
	int sendCmd_std(std::string mssg, bool eod = false);
	// Sends EHLO command, returns response or error code
	int sendEHLO_std();
	// Sends QUIT command, closes connection and socket, returns response or error code
	int sendQUIT_std();
	// Returns true if the keyword is found in the list (supported by SMTP server)
	bool checkEHLOkeyword(std::string keyword); // returns true if the option found
public:
	// Enables authentication, returns true if authentication was enabled
	// Authentication is not supported without TLS/SSL
	bool enableAuthentication(std::string username, std::string password);
	// Opens connection, returns SMTP_OC_* code
	int openConnection();
	// Closes connection properly, closes socket
	void closeConnection();
	// Aborts connection, closes socket
	void abortConnection();
	// Tests connection, returns SMTP_OC_* code
	int testConnection();
	// Sends SMTP command, returns response code or error code; returns 0 if connection closed
	int sendCmd(std::string mssg, bool eod);
	// Returns last error message
	std::string getLastErrMessage() const;
};

#ifdef _ENABLE_TLS_SSL_
// Class smtpConnection_TLS definition
class smtpConnection_TLS: public smtpConnection, public smtpTLS_SSL
{
private:
	bool tls, start_tls;
private:
	// Opens SMTPS connection, returns SMTP_OC_* code
	int openSMTPS();
	// Properly closes connection
	void closeConnection(bool sendQuit);
public:
	//Constructor
	smtpConnection_TLS(const struct smtpParams smtpData, uint8_t verbose, eventInformer *eventInf);
	// Enables authentication, returns true on success
	bool enableAuthentication(std::string username, std::string password);
	// Opens connection, returns SMTP_OC_* code
	int openConnection();
	// Sends SMTP command, returns response code or error code; returns 0 if connection closed
	int sendCmd(std::string mssg, bool eod = false);
	// Properly closes connection
	void closeConnection();
	// Aborts connection
	void abortConnection();
	// Tests connection, returns SMTP_OC_* code
	int testConnection();
	// Callback function on TLS/SSL error
	void onTLSerror(int rc, std::string error_string) override;
};
#endif // _ENABLE_TLS_SSL_

// Class 'protoMailer' definition
class protoMailer
{
protected:
	std::atomic<bool> _init_flag = {false}, _run_flag = {false}, _exit_flag = {false}, _enable_flag = {true};
	std::string mail_srv, smtp_prt;
	struct addrinfo  *smtp_ai = nullptr;
	std::mutex iqmtx, oqmtx, emtx;
	std::condition_variable cv_q, cv_e;
	std::queue<postcard> inQ, outQ, defQ;
	struct smtpErrCount err_count;
	struct smtpStats stats;
	struct smtpRetryLimits rlimits;
	uint8_t verbose_flags;
	bool self_ei;
	class eventInformer *ei;
	SMTP_CONNECTION_CLASS *smtp_conn;
protected:
	// Converts comma delimited string of addresses to vector
	std::vector<std::string> rcptString2Vector(std::string addresses);
};

#endif /* SMTPLIB_HH_ */
