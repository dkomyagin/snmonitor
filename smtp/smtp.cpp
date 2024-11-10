//============================================================================
// Name        : smtplib.cpp
// Author      : Dmitry Komyagin
// Version     : 1.1
// Created on  : Nov 8, 2024
// Copyright   : Public domain
// Description : SMTP embedded client library, Linux, ISO C++14
//============================================================================

/*************************************************************************************************
 * THIRD-PARTY SOFTWARE NOTE
 *
 * The following software might be used in this product:
 *
 * OpenSSL Library, http://openssl-library.org/
 * Read THIRD-PARTY-LICENSES.txt or visit: http://openssl-library.org/source/license/index.html
 *************************************************************************************************/

#include "smtplib.h"
#include "smtp.hh"

using namespace std;

// Returns local time
static string getLocalTime()
{
    time_t rawtime;
    char buffer[32] = {0};

    time(&rawtime);
    strftime(buffer, 32, "%F %T", localtime(&rawtime) );

    return string(buffer);
}
// Returns local time in SMTP format
static string getLocalTimeSMTP()
{
    time_t rawtime;
    char buffer[32] = {0};

    time(&rawtime);
    strftime( buffer, 32, "%a, %d %b %Y %T %z", localtime(&rawtime) );

    return string(buffer);
}
// Same as connect() but with timeout
namespace smtp
{
	static int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen, int timeout)
	{
		int rc, opt;

		// Get socket flags
		if ( ( opt = fcntl(sockfd, F_GETFL, NULL) ) == -1 )
		{
			//cerr << "Unable to get socket flags\n"; // debug
			return -1;
		}
		// Set socket non-blocking
		if ( fcntl(sockfd, F_SETFL, opt|O_NONBLOCK) == -1 )
		{
			//cerr << "Unable to set socket non-blocking\n"; // debug
			return -1;
		}
		// Try to connect
		if( ( rc = connect(sockfd, addr, addrlen) ) == -1 )
		{
			if(errno == EINPROGRESS)
			{
				struct pollfd pfds[1];
				pfds[0].fd = sockfd;
				pfds[0].events = POLLIN|POLLOUT; // read or write
				rc = poll(pfds, 1, timeout);
			}
		}
		else
		{
			rc = 10; // to distinguish from 'poll' return code 0 (which means time-out)
		}
		// Reset socket flags
		if( fcntl(sockfd, F_SETFL, opt) == -1 )
		{
			//cerr << "Unable to reset socket flags\n"; // debug
			return -1;
		}
		// An error occurred in 'connect' or 'poll'
		if(rc < 0)
		{
			return -1;
		}
		// 'poll' timed out
		else if(rc == 0)
		{
			errno = ETIMEDOUT;
			return -1;
		}
		else
		{
			socklen_t len = sizeof(opt);

			if( ( rc = getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &opt, &len) ) == -1 ) // returns 'errno' in 'opt'
			{
				return -1;
			}
			if(opt != 0) // socket has a non-zero error status
			{
				errno = opt;
				return -1;
			}
		}
		return 0;
	}
}
// Converts characters to numbers. Returns 0 if character not a digit
static inline int ch2int(const char ch)
{
    return (int) ( (ch > 48) and (ch < 58) ) ? (ch - '0') : 0;
}
// Returns SMTP code from server reply
static inline int smtp_code(const char *buffer)
{
	return ch2int(buffer[0])*100 + ch2int(buffer[1])*10 +  ch2int(buffer[2]);
}
// Replaces LF with CRLF
static string replaceLFwithCRLF(string txt)
{
	size_t pos = 0;

	while(true)
	{
		pos = txt.find( '\n', pos );
		if(pos == string::npos) break;
		if( (pos == 0)  or (txt[pos - 1] != '\r') )
		{
			txt.insert(pos, "\r");
			pos += 2;
		}
		else
		{
			++pos;
		}
	}
	return txt;
}
// Returns elapsed time
static inline seconds elapsed_time(steady_time_point_t end, steady_time_point_t start)
{
    return chrono::duration_cast<chrono::seconds>(end - start);
}

// Structure 'smtpErrCount' methods
// Clear all counters
void smtpErrCount::clear()
{
    setup_err   = 0;
    socket_err  = 0;
    oc_err      = 0;
    tls_sys_err = 0;
    tls_con_err = 0;
    tls_vrf_err = 0;
    auth_m_err  = 0;
    auth_c_err  = 0;
    send_err    = 0;
}

// Class 'smtpEventInformer' methods
// Event informer
void smtpEventInformer::onEvent(const eventData &info)
{
    //
    if(info.routine == SMTP_LIB_MAILER_METHOD_ONSENDERROR)
    {
        cout << getLocalTime() + "  " + info.message + "\n";
        return;
    }
    //
    if(info.type == SMTP_LIB_HANDLER_STOPPED)
    {
        cout << info.message + "\n";
        return;
    }
    //
    if(info.type == SMTP_LIB_TLS_NOT_SUPPORTED)
    {
        cout << getLocalTime() + "  " + info.message + "\n";
        return;
    }
    //
    if(info.message == "")
    {
        cout << getLocalTime() + "  " + info.module + "::" + info.routine + ": no message provided\n";
    }
    else if(info.type < 0)
    {
        cerr << getLocalTime() + "  " + info.module + "::" + info.routine + ": " + info.message +"\n";
    }
    else
    {
        cout << getLocalTime() + "  " + info.message +"\n";
    }
}

#ifdef _ENABLE_TLS_SSL_

#if OPENSSL_VERSION_MAJOR < 3
    #define SSL_get0_peer_certificate SSL_get_peer_certificate
    static inline int SSL_CTX_load_verify_dir(SSL_CTX *ctx, const char *CApath)
    {
        return SSL_CTX_load_verify_locations(ctx, nullptr, CApath);
    }
#endif // OPENSSL_VERSION_MAJOR

// Returns 'true' on a valid IP address and 'false' otherwise
static bool isIPaddr(const char* address)
{
    char buf[sizeof(sockaddr_in6)];

    return ( (inet_pton( AF_INET, address, &buf ) == 1) or (inet_pton( AF_INET6, address, &buf ) == 1) );
}
// Converts date to string
string ASN1_TIME_string(const ASN1_TIME *tm)
{
	BIO *bmem = BIO_new( BIO_s_mem() );
	string timeStr;

    if( ASN1_TIME_print(bmem, tm) )
    {
        BUF_MEM * bptr;
        BIO_get_mem_ptr(bmem, &bptr);
        timeStr.assign( string(bptr->data, bptr->length) );
    }
    else
    {
    	timeStr = "";
    }
    BIO_free_all(bmem);
    return timeStr;
}

// Class 'smtpTLS_SSL' methods
// Constructor
smtpTLS_SSL::smtpTLS_SSL(uint8_t verbose, eventInformer *eventInf)
{
    _ei = eventInf;
    _verbose_flags = verbose;
}
// Destructor
smtpTLS_SSL::~smtpTLS_SSL()
{
    if(ctx != nullptr) SSL_CTX_free(ctx);
}
// Opens TLS/SSL connection, returns SMTP_OC_* code
int smtpTLS_SSL::connectSSL(const int socket)
{
	int rc;
	struct eventData evdata = {SMTP_LIB_CLASS_SMTP_TLS_SSL, SMTP_LIB_TLSSSL_METHOD_CONNECT_SSL, "", 0};

	// Clear fatal error flag
	fatal_ssl_err = false;
	// Create a new SSL_CTX object
	if(ctx == nullptr)
	{
		ctx = SSL_CTX_new( TLS_client_method() );
	    if(ctx == nullptr)
	    {
	    	last_tls_mssg = "Unable to create SSL_CTX object";
	    	onTLSerror(SMTP_OC_TLS_SYS_ERR, last_tls_mssg);
			if(_verbose_flags & SMTP_SSL_CONNECTION_DEBUG)
			{
				ERR_print_errors_fp(stderr);
		        evdata.message = last_tls_mssg;
		        evdata.type = SMTP_LIB_SSLTLS_SETUP_ERROR;
		        _ei->onEvent(evdata);
			}
	        return SMTP_OC_TLS_SYS_ERR;
	    }
	    //if( SSL_CTX_load_verify_dir(ctx, SSL_CERT_DEFAULT_DIR) != 1 )
	    if( SSL_CTX_load_verify_locations(ctx, nullptr, SSL_CERT_DEFAULT_DIR) != 1 )
	    {
	    	SSL_CTX_free(ctx);
	    	ctx = nullptr;
	    	last_tls_mssg = "Unable to add CA certificates location: '" + string(SSL_CERT_DEFAULT_DIR);
	    	onTLSerror(SMTP_OC_TLS_SYS_ERR, last_tls_mssg);
			if(_verbose_flags & SMTP_SSL_CONNECTION_DEBUG)
			{
                evdata.message = last_tls_mssg;
                evdata.type = SMTP_LIB_SSLTLS_SETUP_ERROR;
                _ei->onEvent(evdata);
			}
	    	return SMTP_OC_TLS_SYS_ERR;
	    }
	}
	// Create a new SSL object
	ssl = SSL_new(ctx);
	if(ssl == nullptr)
	{
    	last_tls_mssg = "Unable to create SSL object";
    	onTLSerror(SMTP_OC_TLS_SYS_ERR, last_tls_mssg);
		if(_verbose_flags & SMTP_SSL_CONNECTION_DEBUG)
		{
            evdata.message = last_tls_mssg;
            evdata.type = SMTP_LIB_SSLTLS_SETUP_ERROR;
            _ei->onEvent(evdata);
		}
		return SMTP_OC_TLS_SYS_ERR;
	}
	// Set verification environment
	if(cverify)
	{
		// Set SSL host flags
		SSL_set_hostflags(ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
		// Set server hostname
		if(pverify)
		{
			if( !SSL_set1_host( ssl, peer_name.c_str() ) )
			{
				SSL_free(ssl);
		    	last_tls_mssg = "Unable to set hostname for SSL verification";
		    	onTLSerror(SMTP_OC_TLS_SYS_ERR, last_tls_mssg);
				if( _verbose_flags & SMTP_SSL_CONNECTION_DEBUG )
				{
		            evdata.message = last_tls_mssg;
		            evdata.type = SMTP_LIB_SSLTLS_SETUP_ERROR;
		            _ei->onEvent(evdata);
				}
				return SMTP_OC_TLS_SYS_ERR;
			}
		}
		// Enable peer verification
		SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
	}
	// Bind SSL to TCP socket
	if( SSL_set_fd(ssl, socket) == 0 )
	{
		SSL_free(ssl);
    	last_tls_mssg = "Unable to bind SSL descriptor to TCP socket";
    	onTLSerror(SMTP_OC_TLS_SYS_ERR, last_tls_mssg);
		if( _verbose_flags & SMTP_SSL_CONNECTION_DEBUG )
		{
            evdata.message = last_tls_mssg;
            evdata.type = SMTP_LIB_SSLTLS_SETUP_ERROR;
            _ei->onEvent(evdata);
		}
		return SMTP_OC_TLS_SYS_ERR;
	}
	// Connect
	if ( ( rc = SSL_connect(ssl) ) != 1 )
	{
    	last_tls_mssg = "Unable to establish SSL connection, code: " + to_string( SSL_get_error(ssl, rc) );
		SSL_free(ssl);
    	onTLSerror(SMTP_OC_TLS_CON_ERR, last_tls_mssg);
		if(_verbose_flags & SMTP_SSL_CONNECTION_DEBUG)
		{
            evdata.message = last_tls_mssg;
            evdata.type = SMTP_LIB_SSLTLS_CONNECTION_ERROR;
            _ei->onEvent(evdata);
		}
		return SMTP_OC_TLS_CON_ERR;
	}
	else
	{
		_tls_open = true;
	}
	// Check if SMTP server sent SSL certificate
	// Due to the protocol definition, TLS/SSL server will always send a certificate, if present
	if( SSL_get0_peer_certificate(ssl) == nullptr )
	{
		closeSSL(false);
    	last_tls_mssg = "No SSL certificate was presented by SMTP server";
    	onTLSerror(SMTP_OC_TLS_VRF_ERR, last_tls_mssg);
		if(_verbose_flags & SMTP_SSL_CONNECTION_DEBUG)
		{
            evdata.message = last_tls_mssg;
            evdata.type = SMTP_LIB_SSLTLS_SRV_VERIFICATION_ERROR;
            _ei->onEvent(evdata);
		}
		return SMTP_OC_TLS_VRF_ERR;
	}
	// Verify SSL certificate
	if(cverify)
	{
		rc = SSL_get_verify_result(ssl);
		if(rc != X509_V_OK)
		{
			switch(rc) // x509_vfy.h
			{
				case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
					last_tls_mssg = "SSL certificate error: Unable to verify self-signed certificate";
					break;
				case X509_V_ERR_HOSTNAME_MISMATCH:
					last_tls_mssg = "SSL certificate error: Host name mismatch";
					break;
				case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
					last_tls_mssg = "SSL certificate error: Unable to get issuer certificate locally";
					break;
				default:
					last_tls_mssg = "SSL certificate error, code: " + to_string(rc);
			}
			closeSSL(false);
			onTLSerror(SMTP_OC_TLS_VRF_ERR, last_tls_mssg);
			if(_verbose_flags & SMTP_SSL_CONNECTION_DEBUG)
			{
	            evdata.message = last_tls_mssg;
	            evdata.type = SMTP_LIB_SSLTLS_SRV_VERIFICATION_ERROR;
	            _ei->onEvent(evdata);
			}
			return SMTP_OC_TLS_VRF_ERR;
		}
	}
	return SMTP_OC_SSL_OK;
}
// Properly closes TLS/SSL connection
int smtpTLS_SSL::closeSSL(bool sendQuit)
{
	if(_tls_open)
	{
		if(sendQuit)
		{
			return sendQUIT_tls();
		}
		else
		{
			// SSL_shutdown() should not be called if a previous fatal error has occurred on a connection
			if(not fatal_ssl_err)
			{
				SSL_shutdown(ssl);
				readSrvResponse(true); // to properly finalize SSL connection
			}
			_tls_open = false;
			SSL_free(ssl);
			return 0;
		}
	}
	return 1;
}
// Aborts TLS/SSL connection
void smtpTLS_SSL::abortSSL()
{
	if(_tls_open)
	{
		_tls_open = false;
		SSL_free(ssl);
	}
}
// Set verification for SMTP server
void smtpTLS_SSL::setVerification(bool certVerification, const string peerName = "")
{
	if(certVerification)
	{
		cverify = true;
		if( !peerName.empty() and !isIPaddr( peerName.c_str() ) )
		{
			pverify = true;
			peer_name = peerName;
		}
	}
	else
	{
		cverify = false;
		pverify = false;
	}
}
// Reads SMTP server reply, returns return code or error code
int smtpTLS_SSL::readSrvResponse(bool on_closing)
{
	int l, rc;
	struct eventData evdata = {SMTP_LIB_CLASS_SMTP_TLS_SSL, SMTP_LIB_TLSSSL_METHOD_SRV_RESPONSE, "", 0};
	char rbuffer[SMTP_SSL_BUF_SZ] = {0};

	l = SSL_read( ssl, rbuffer, sizeof(rbuffer) );
	if( not on_closing and (l <= 0) ) // read error
	{
		rc = SSL_get_error( ssl, l );
		last_tls_mssg = string( ERR_error_string( rc, NULL ) );
		onTLSerror( rc, last_tls_mssg );
		if(_verbose_flags & SMTP_COMMAND_DEBUG)
		{
            evdata.message = "TLS read error: " + last_tls_mssg;
            evdata.type = SMTP_LIB_TLS_READ_ERROR;
            _ei->onEvent(evdata);
		}
		if( (rc == SSL_ERROR_SSL) or (rc == SSL_ERROR_SYSCALL) )
		{
			fatal_ssl_err = true;
		}
		return SMTP_TLS_SSL_READ_ERR;
	}
	if(not on_closing)
	{
		last_tls_mssg = string(rbuffer);
		last_tls_mssg.erase( last_tls_mssg.size() - 2, 2 ); // remove "\r\n"
		if(_verbose_flags & SMTP_COMMAND_DEBUG)
		{
            evdata.message = "SMTP TLS server reply:\n" + last_tls_mssg;
            evdata.type = SMTP_LIB_SMTP_TLS_SRV_REPLY;
            _ei->onEvent(evdata);
		}
	}
	return smtp_code(rbuffer);
}
// Output server certificates to console
void smtpTLS_SSL::coutSrvCerts() const
{
	X509 *cert = SSL_get0_peer_certificate(ssl); // get the server's certificate
	if(cert != nullptr)
	{
		cout << "Server SSL certificates:\n";
	    cout << "Subject: ";
	    X509_NAME_print_ex_fp( stdout, X509_get_subject_name(cert), 0, XN_FLAG_ONELINE );
	    cout << endl;
	    cout << "Issuer:  ";
		X509_NAME_print_ex_fp( stdout, X509_get_issuer_name(cert), 0, XN_FLAG_ONELINE );
	    cout << endl;
	    cout << "Version: " << X509_get_version(cert) + 1 << endl;
	    cout << "Not before: " + ASN1_TIME_string( X509_get_notBefore(cert) ) + "\n";
 	    cout << "Not after:  " + ASN1_TIME_string( X509_get_notAfter(cert) ) +  "\n";
	    cout << endl;
	}
	else
	{
		cout << "No SSL certificates was received\n";
	}
}
// Sends SMTP command, returns response or error code
int smtpTLS_SSL::sendCmd_tls(string mssg, bool eod)
{
	int l, rc;
	struct eventData evdata = {SMTP_LIB_CLASS_SMTP_TLS_SSL, SMTP_LIB_TLSSSL_METHOD_SEND_CMD_TLS, "", 0};
	char rbuffer[SMTP_SSL_BUF_SZ] = {0};

	if(_verbose_flags & SMTP_COMMAND_DEBUG)
	{
        evdata.message = "SMTP TLS command:\n" + mssg;
        evdata.type = SMTP_LIB_SMTP_TLS_COMMAND;
        _ei->onEvent(evdata);
	}
	if(eod)
		mssg += "\r\n.\r\n";
	else
		mssg += "\r\n";
	l = SSL_write( ssl, mssg.c_str(), mssg.size() );
	if(l <= 0) // send error
	{
		rc = SSL_get_error( ssl, l );
		last_tls_mssg = string( ERR_error_string( rc, NULL ) );
		onTLSerror(rc, last_tls_mssg);
		if(_verbose_flags & SMTP_COMMAND_DEBUG)
		{
	        evdata.message = "TLS send error: " + last_tls_mssg;
	        evdata.type = SMTP_LIB_TLS_SEND_ERROR;
	        _ei->onEvent(evdata);
		}
		if( (rc == SSL_ERROR_SSL) or (rc == SSL_ERROR_SYSCALL) )
		{
			fatal_ssl_err = true;
		}
		return SMTP_TLS_SSL_SEND_ERR;
	}
	l = SSL_read( ssl, rbuffer, sizeof(rbuffer) );
	if(l <= 0) // read error
	{
		rc = SSL_get_error(ssl, l);
		last_tls_mssg = string( ERR_error_string(rc, NULL) );
		onTLSerror(rc, last_tls_mssg);
		if(_verbose_flags & SMTP_COMMAND_DEBUG)
		{
            evdata.message = "TLS read error: " + last_tls_mssg;
            evdata.type = SMTP_LIB_TLS_READ_ERROR;
            _ei->onEvent(evdata);
		}
		if( (rc == SSL_ERROR_SSL) or (rc == SSL_ERROR_SYSCALL) )
		{
			fatal_ssl_err = true;
		}
		return SMTP_TLS_SSL_READ_ERR;
	}
	last_tls_mssg = string(rbuffer);
	last_tls_mssg.erase(last_tls_mssg.size() - 2, 2); // remove "\r\n"
	if(_verbose_flags & SMTP_COMMAND_DEBUG)
	{
        evdata.message = "SMTP TLS server reply:\n" + last_tls_mssg;
        evdata.type = SMTP_LIB_SMTP_TLS_SRV_REPLY;
        _ei->onEvent(evdata);
	}
	return smtp_code(rbuffer);
}
// Sends EHLO command, returns response or error code
int smtpTLS_SSL::sendEHLO_tls(const string& hostName)
{
	int l, rc;
	struct eventData evdata = {SMTP_LIB_CLASS_SMTP_TLS_SSL, SMTP_LIB_TLSSSL_METHOD_SEND_EHLO_TLS, "", 0};
	char rbuffer[SMTP_BUF_SZ] = {0};
	const string mssg = "EHLO " + hostName + "\r\n";
	ehlo_keywords.clear();
	auth_methods.clear();
	if(_verbose_flags & SMTP_COMMAND_DEBUG)
	{
        evdata.message = "SMTP TLS command:\nEHLO " + hostName;
        evdata.type = SMTP_LIB_SMTP_TLS_COMMAND;
        _ei->onEvent(evdata);
	}
	l = SSL_write( ssl, mssg.c_str(), mssg.size() );
	if(l <= 0) // send error
	{
		rc = SSL_get_error( ssl, l );
		last_tls_mssg = string( ERR_error_string(rc, NULL) );
		onTLSerror(rc, last_tls_mssg);
		if(_verbose_flags & SMTP_COMMAND_DEBUG)
		{
            evdata.message = "TLS send error: " + last_tls_mssg;
            evdata.type = SMTP_LIB_TLS_SEND_ERROR;
            _ei->onEvent(evdata);
		}
		if( (rc == SSL_ERROR_SSL) or (rc == SSL_ERROR_SYSCALL) )
		{
			fatal_ssl_err = true;
		}
		return SMTP_TLS_SSL_SEND_ERR;
	}
	l = SSL_read( ssl, rbuffer, sizeof(rbuffer) );
	if(l <= 0) // read error
	{
		rc = SSL_get_error(ssl, l);
		last_tls_mssg = string( ERR_error_string(rc, NULL) );
		onTLSerror(rc, last_tls_mssg);
		if(_verbose_flags & SMTP_COMMAND_DEBUG)
		{
            evdata.message = "TLS read error: " + last_tls_mssg;
            evdata.type = SMTP_LIB_TLS_READ_ERROR;
            _ei->onEvent(evdata);
		}
		if( (rc == SSL_ERROR_SSL) or (rc == SSL_ERROR_SYSCALL) )
		{
			fatal_ssl_err = true;
		}
		return SMTP_TLS_SSL_READ_ERR;
	}
	last_tls_mssg = string(rbuffer);
	last_tls_mssg.erase(last_tls_mssg.size() - 2, 2); // remove "\r\n"
	if( _verbose_flags & SMTP_COMMAND_DEBUG  )
	{
        evdata.message = "SMTP TLS server reply:\n" + last_tls_mssg;
        evdata.type = SMTP_LIB_SMTP_TLS_SRV_REPLY;
        _ei->onEvent(evdata);
	}
	rc = smtp_code(rbuffer);
	if(rc == SMTP_CODE_OK)
	{
	    stringstream ss(rbuffer);
		string rp;
		while( getline(ss, rp, '\n') )
		{
		    rp = rp.substr(4, rp.size() - 5);
			transform(rp.begin(), rp.end(), rp.begin(), ::toupper);
			ehlo_keywords.insert(rp);
			if( rp.rfind("AUTH ", 0) == 0 )
			{
			    stringstream iss( rp.substr(5) );
				string meth;
				while( getline(iss, meth, ' ') )  if( !meth.empty() ) auth_methods.insert(meth);
			}
		}
	}
	return rc;
}
// Sends QUIT command, closes TLS/SSL connection and socket, returns response or error code
int smtpTLS_SSL::sendQUIT_tls()
{
	int l = 0, rc = 0;
	struct eventData evdata = {SMTP_LIB_CLASS_SMTP_TLS_SSL, SMTP_LIB_TLSSSL_METHOD_SEND_QUIT_TLS, "", 0};
	char rbuffer[SMTP_BUF_SZ] = {0};
	const char *mssg = "QUIT\r\n";

	if(_verbose_flags & SMTP_COMMAND_DEBUG)
	{
        evdata.message = "SMTP TLS command:\nQUIT";
        evdata.type = SMTP_LIB_SMTP_TLS_COMMAND;
        _ei->onEvent(evdata);
	}
	l = SSL_write( ssl, mssg, strlen(mssg) );
	if(l <= 0) // send error
	{
		rc = SSL_get_error(ssl, l);
		last_tls_mssg = string( ERR_error_string(rc, NULL) );
		onTLSerror(rc, last_tls_mssg);
		if(_verbose_flags & SMTP_COMMAND_DEBUG)
		{
            evdata.message = "TLS send error: " + last_tls_mssg;
            evdata.type = SMTP_LIB_TLS_SEND_ERROR;
            _ei->onEvent(evdata);
		}
		if( (rc == SSL_ERROR_SSL) or (rc == SSL_ERROR_SYSCALL) )
		{
			fatal_ssl_err = true;
		}
		SSL_free(ssl);
		_tls_open = false;
		return SMTP_TLS_SSL_SEND_ERR;
	}
	l = SSL_read( ssl, rbuffer, sizeof(rbuffer) );
	if(l <= 0) // read error
	{
		rc = SSL_get_error(ssl, l);
		last_tls_mssg = string( ERR_error_string(rc, NULL) );
		onTLSerror(rc, last_tls_mssg);
		if(_verbose_flags & SMTP_COMMAND_DEBUG)
		{
            evdata.message = "TLS read error: " + last_tls_mssg;
            evdata.type = SMTP_LIB_TLS_READ_ERROR;
            _ei->onEvent(evdata);
		}
		if( (rc == SSL_ERROR_SSL) or (rc == SSL_ERROR_SYSCALL) )
		{
			fatal_ssl_err = true;
		}
		SSL_free(ssl);
		_tls_open = false;
		return SMTP_TLS_SSL_READ_ERR;
	}
	/*----------------------------------------------------------------------------------------------
	 * Note:
	 * When receiving 'QUIT' command, SMTP server immediately sends a TCP packet with FIN flag set
	 * or sets FIN flag directly in the acknowledgment.
	 * Thus there is no need to shutdown the SSL connection but it is necessary to read data from
	 * the TCP socket to properly close the TCP connection.
	 -----------------------------------------------------------------------------------------------*/
	SSL_free(ssl);
	_tls_open = false;

	last_tls_mssg = string(rbuffer);
	last_tls_mssg.erase(last_tls_mssg.size() - 2, 2); // remove "\r\n"
	if(_verbose_flags & SMTP_COMMAND_DEBUG)
	{
        evdata.message = "SMTP TLS server reply:\n" + last_tls_mssg;
        evdata.type = SMTP_LIB_SMTP_TLS_SRV_REPLY;
        _ei->onEvent(evdata);
	}
	return smtp_code(rbuffer);
}
// Authentication, returns the last SMTP return code or error code
// Only PLAIN and LOGIN authentication methods are supported
int smtpTLS_SSL::Authenticate(const string& username, const string& password)
{
	int rc;
	struct eventData evdata = {SMTP_LIB_CLASS_SMTP_TLS_SSL, SMTP_LIB_TLSSSL_METHOD_AUTH, "", 0};

	if( auth_methods.find("PLAIN") != auth_methods.end() )
	{
		if( ( rc = sendCmd_tls("AUTH PLAIN") ) != SMTP_CODE_SRV_CHALLNGE )
		{
			if(_verbose_flags & SMTP_SSL_CONNECTION_DEBUG)
			{
	            evdata.message = "SMTP server cannot start PLAIN authentication: " + last_tls_mssg;
	            evdata.type = SMTP_LIB_SSLTLS_AUTH_METHOD_ERROR;
	            _ei->onEvent(evdata);
			}
			return rc;
		}
		rc = sendCmd_tls( SMTP_AUTH_PLAIN_encoder("", username, password) );
	}
	else if( auth_methods.find("LOGIN") != auth_methods.end() )
	{
		if( ( rc = sendCmd_tls("AUTH LOGIN") ) != SMTP_CODE_SRV_CHALLNGE )
		{
			if(_verbose_flags & SMTP_SSL_CONNECTION_DEBUG)
			{
                evdata.message = "SMTP server cannot start LOGIN authentication: " + last_tls_mssg;
                evdata.type = SMTP_LIB_SSLTLS_AUTH_METHOD_ERROR;
                _ei->onEvent(evdata);
			}
			return rc;
		}
		if( ( rc = sendCmd_tls( encode_base64(username) ) ) != SMTP_CODE_SRV_CHALLNGE )
		{
			if(_verbose_flags & SMTP_SSL_CONNECTION_DEBUG)
			{
                evdata.message = "SMTP server LOGIN authentication 'username' problem: " + last_tls_mssg;
                evdata.type = SMTP_LIB_SSLTLS_AUTH_METHOD_ERROR;
                _ei->onEvent(evdata);
			}
			return rc;
		}
		rc = sendCmd_tls( encode_base64(password) );
	}
	else
	{
		rc = SMTP_OC_AUTH_M_ERR;
		last_tls_mssg = "No common authentication method";
		onTLSerror(rc, last_tls_mssg);
		if(_verbose_flags & SMTP_SSL_CONNECTION_DEBUG)
		{
            evdata.message = "SMTP server authentication failed: " + last_tls_mssg;
            evdata.type = SMTP_LIB_SSLTLS_AUTH_METHOD_ERROR;
            _ei->onEvent(evdata);
		}
	}
	return rc;
}
#endif // _ENABLE_TLS_SSL_

// Class 'smtpConnection' methods
// Constructor
smtpConnection::smtpConnection(const struct smtpParams smtpData, uint8_t verbose, eventInformer *eventInf)
{
	smtp_data = smtpData;
	verbose_flags = verbose;
	ei = eventInf;
}
// Destructor
smtpConnection::~smtpConnection()
{
	close(sd);
	if(smtp_ai != nullptr) freeaddrinfo(smtp_ai);
}
// Opens socket and returns socket descriptor on success; on error, -1 is returned
int smtpConnection::openSocket()
{
    struct eventData evdata = {SMTP_LIB_CLASS_STD_CONNECTION, SMTP_LIB_STD_CONN_METHOD_OPEN_SD, "", 0};

	int sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(sd == -1)
	{
		last_err_mssg = string( strerror(errno) );
		if(verbose_flags & SMTP_CONNECTION_DEBUG)
		{
	        evdata.message = "Failed to create socket descriptor: " + last_err_mssg;
	        evdata.type = SMTP_LIB_ERROR_SOCKET;
	        ei->onEvent(evdata);
		}
	   	return -1;
	}
	// Set timeout for protocol
	struct timeval tv = {.tv_sec = SMTP_REQ_RETRY_TIMEOUT};
	if( setsockopt( sd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv) ) == -1 )
	{
	   	close(sd);
	   	last_err_mssg = string( strerror(errno) );
		if( verbose_flags & SMTP_CONNECTION_DEBUG )
		{
	        evdata.message = "Failed to set socket timeout: " + last_err_mssg;
	        evdata.type = SMTP_LIB_ERROR_TO_OPTION;
	        ei->onEvent(evdata);
		}
		return -1;
	}
	last_err_mssg = "Success";
	return sd;
}
// Connection environment setup. On success returns 0; on error, -1 is returned
int smtpConnection::setupConnection()
{
	int rc;
	struct eventData evdata = {SMTP_LIB_CLASS_STD_CONNECTION, SMTP_LIB_STD_CONN_METHOD_SETUP_CONN, "", 0};
	struct addrinfo  hints;
	char hname[HOST_NAME_MAX + 1];

    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_CANONNAME|AI_NUMERICSERV;
    hints.ai_protocol = IPPROTO_TCP;

	if( gethostname( hname, sizeof(hname) ) != 0 )
	{
		last_err_mssg = "Failed to get own hostname: " + string( strerror(errno) );
		if(verbose_flags & SMTP_CONNECTION_DEBUG)
		{
	        evdata.message = last_err_mssg;
	        evdata.type = SMTP_LIB_ERROR_GET_OWN_HOSTNAME;
	        ei->onEvent(evdata);
		}
		return -1;
	}
	else
	{
		host_name = string(hname);
	}
	if( ( rc = getaddrinfo(smtp_data.srv.c_str(), smtp_data.port.c_str(), &hints, &smtp_ai) ) != 0 )
	{
		if(rc == EAI_AGAIN)
		{
			last_err_mssg = "Hostname not known or temporary failure in name resolution";
			if(verbose_flags & SMTP_CONNECTION_DEBUG)
			{
	            evdata.message = "SMTP server setup error: " + last_err_mssg;
	            evdata.type = SMTP_LIB_ERROR_DNS_RESOLUTION;
	            ei->onEvent(evdata);
			}
		}
		else
		{
			last_err_mssg = string( gai_strerror(rc) );
			if(verbose_flags & SMTP_CONNECTION_DEBUG)
			{
	            evdata.message = "SMTP server setup error: " + last_err_mssg;
	            evdata.type = SMTP_LIB_ERROR_DNS_RESOLUTION;
	            ei->onEvent(evdata);
			}
		}
		return -1;
	}
	else if(verbose_flags & SMTP_CONNECTION_DEBUG)
	{
		char buffer[INET6_ADDRSTRLEN];
		string infoMssg;
		inet_ntop( AF_INET, &( ( (struct sockaddr_in *) smtp_ai->ai_addr )->sin_addr ), buffer, INET6_ADDRSTRLEN );
		if( ( strlen(buffer) == strlen(smtp_ai->ai_canonname) ) and ( strcmp( smtp_ai->ai_canonname, buffer ) == 0 ) )
		{
		    infoMssg = "SMTP server: " + string(smtp_ai->ai_canonname) + ", port: " + smtp_data.port;
		}
		else
		{
		    infoMssg = "SMTP server: " + string(smtp_ai->ai_canonname) + " at " + string(buffer) + ", port: " + smtp_data.port;
		}
        // Put message
        evdata.message = infoMssg;
        evdata.type = SMTP_LIB_SETUP_SUCCESS;
        ei->onEvent(evdata);
	}
	setup = true;
	return 0;
}
// Sends SMTP command, returns response or error code
int smtpConnection::sendCmd_std(string mssg, bool eod)
{
	ssize_t l;
	struct eventData evdata = {SMTP_LIB_CLASS_STD_CONNECTION, SMTP_LIB_STD_CONN_METHOD_SEND_CMD_STD, "", 0};
	char rbuffer[SMTP_BUF_SZ] = {0};

	if(verbose_flags & SMTP_COMMAND_DEBUG)
	{
	    evdata.message = "SMTP command:\n" + mssg;
	    evdata.type = SMTP_LIB_SMTP_COMMAND;
	    ei->onEvent(evdata);
	}
	if(eod)
		mssg += "\r\n.\r\n";
	else
		mssg += "\r\n";
	l = send(sd, mssg.c_str(), mssg.size(), 0);
	if(l <= 0) // send error
	{
		fatal_conn_err = true;
		last_err_mssg = string( strerror(errno) );
		if(verbose_flags & SMTP_COMMAND_DEBUG)
		{
	        evdata.message = "TCP send error: " + last_err_mssg;
	        evdata.type = SMTP_LIB_TCP_SEND_ERROR;
	        ei->onEvent(evdata);
		}
		return SMTP_TCP_SEND_ERR;
	}
	l = read( sd, rbuffer, sizeof(rbuffer) );
	if(l <= 0) // read error
	{
		fatal_conn_err = true;
		last_err_mssg = string( strerror(errno) );
		if(verbose_flags & SMTP_COMMAND_DEBUG)
		{
	        evdata.message = "TCP read error: " + last_err_mssg;
	        evdata.type = SMTP_LIB_TCP_READ_ERROR;
	        ei->onEvent(evdata);
		}
		return SMTP_TCP_READ_ERR; // read error
	}

	last_err_mssg = string(rbuffer);
	last_err_mssg.erase( last_err_mssg.size() - 2, 2 ); // remove "\r\n"
	if(verbose_flags & SMTP_COMMAND_DEBUG)
	{
	    evdata.message = "SMTP server reply:\n" + last_err_mssg;
	    evdata.type = SMTP_LIB_SMTP_SRV_REPLY;
	    ei->onEvent(evdata);
	}
	return smtp_code(rbuffer);
}
// Sends EHLO command, returns response or error code
int smtpConnection::sendEHLO_std()
{
	ssize_t l;
	struct eventData evdata = {SMTP_LIB_CLASS_STD_CONNECTION, SMTP_LIB_STD_CONN_METHOD_SEND_EHLO_STD, "", 0};
	int rc;
	char rbuffer[SMTP_BUF_SZ] = {0};
	string mssg = "EHLO " + host_name + "\r\n";
	ehlo_keywords.clear();

	if(verbose_flags & SMTP_COMMAND_DEBUG)
	{
	    evdata.message = "SMTP command:\nEHLO " + host_name;
	    evdata.type = SMTP_LIB_SMTP_COMMAND;
	    ei->onEvent(evdata);
	}
	l = send(sd, mssg.c_str(), mssg.size(), 0);
	if(l <= 0) // send error
	{
		fatal_conn_err = true;
		last_err_mssg = string( strerror(errno) );
		if(verbose_flags & SMTP_COMMAND_DEBUG)
		{
	        evdata.message = "TCP send error: " + last_err_mssg;
	        evdata.type = SMTP_LIB_TCP_SEND_ERROR;
	        ei->onEvent(evdata);
		}
		return SMTP_TCP_SEND_ERR;
	}
	l = read( sd, rbuffer, sizeof(rbuffer) );
	if( l <= 0 ) // read error
	{
		fatal_conn_err = true;
		last_err_mssg = string( strerror(errno) );
		if( verbose_flags & SMTP_COMMAND_DEBUG )
		{
	        evdata.message = "TCP read error: " + last_err_mssg;
	        evdata.type = SMTP_LIB_TCP_READ_ERROR;
	        ei->onEvent(evdata);
		}
		return SMTP_TCP_READ_ERR;
	}
	last_err_mssg = string(rbuffer);
	last_err_mssg.erase( last_err_mssg.size() - 2, 2 ); // remove "\r\n"
	if( verbose_flags & SMTP_COMMAND_DEBUG )
	{
	    evdata.message = "SMTP server reply:\n" + last_err_mssg;
	    evdata.type = SMTP_LIB_SMTP_SRV_REPLY;
	    ei->onEvent(evdata);
	}
	rc = smtp_code(rbuffer);
	if( rc == SMTP_CODE_OK )
	{
		  stringstream ss(rbuffer);
		  string rp;
		  while( getline( ss, rp, '\n' ) )
		  {
			  rp = rp.substr( 4, rp.size() - 5 );
			  transform( rp.begin(), rp.end(), rp.begin(), ::toupper);
			  ehlo_keywords.insert(rp);
		  }
	}
	return rc;
}
// Sends QUIT command, closes connection and socket, returns response or error code
int smtpConnection::sendQUIT_std()
{
	ssize_t l;
	struct eventData evdata = {SMTP_LIB_CLASS_STD_CONNECTION, SMTP_LIB_STD_CONN_METHOD_SEND_QUIT_STD, "", 0};
	char rbuffer[SMTP_BUF_SZ] = {0};
	const char *mssg = "QUIT\r\n";

	if(verbose_flags & SMTP_COMMAND_DEBUG)
	{
	    evdata.message = "SMTP command:\nQUIT";
	    evdata.type = SMTP_LIB_SMTP_COMMAND;
	    ei->onEvent(evdata);
	}
	l = send(sd, mssg, strlen(mssg), 0);
	if(l <= 0) // send error
	{
		fatal_conn_err = true;
		last_err_mssg = string( strerror(errno) );
		if( verbose_flags & SMTP_COMMAND_DEBUG )
		{
	        evdata.message = "TCP send error: " + last_err_mssg;
	        evdata.type = SMTP_LIB_TCP_SEND_ERROR;
	        ei->onEvent(evdata);
	        abortConnection();
		}
		abortConnection();
		return SMTP_TCP_SEND_ERR;
	}
	l = read( sd, rbuffer, sizeof(rbuffer) );
	if(l <= 0) // read error
	{
		fatal_conn_err = true;
		last_err_mssg = string( strerror(errno) );
		if( verbose_flags & SMTP_COMMAND_DEBUG )
		{
	        evdata.message = "TCP read error: " + last_err_mssg;
	        evdata.type = SMTP_LIB_TCP_READ_ERROR;
	        ei->onEvent(evdata);
		}
		abortConnection();
		return SMTP_TCP_READ_ERR;
	}
	abortConnection();
	last_err_mssg = string(rbuffer);
	last_err_mssg.erase( last_err_mssg.size() - 2, 2 ); // remove "\r\n"
	if(verbose_flags & SMTP_COMMAND_DEBUG)
	{
	    evdata.message = "SMTP server reply:\n" + last_err_mssg;
	    evdata.type = SMTP_LIB_SMTP_SRV_REPLY;
	    ei->onEvent(evdata);
	}
	return smtp_code(rbuffer);
}
// Returns true if the keyword is found in the list (supported by SMTP server)
bool smtpConnection::checkEHLOkeyword(string keyword)
{
	if( ehlo_keywords.find(keyword) == ehlo_keywords.end() )
		return false;
	else
		return true;
}
// Enables authentication, returns true if authentication was enabled
// Authentication is not supported without TLS/SSL
bool smtpConnection::enableAuthentication(string username, string password)
{
	auth = false; // Authentication is not supported without TLS/SSL
	return auth;
}
// Opens connection, returns SMTP_OC_* code
int smtpConnection::openConnection()
{
    struct eventData evdata = {SMTP_LIB_CLASS_STD_CONNECTION, SMTP_LIB_STD_CONN_METHOD_OPEN_CONN, "", 0};
	char rbuffer[SMTP_BUF_SZ] = {0};

	_std_open = false;
	fatal_conn_err = false;

    if(verbose_flags & SMTP_CONNECTION_DEBUG)
    {
        evdata.message = "Opening standard connection";
        evdata.type = SMTP_LIB_DEBUG;
        ei->onEvent(evdata);
    }
	// Setup connection
	if(!setup)
	{
		if( setupConnection() != 0 ) return SMTP_OC_SETUP_ERR;
	}
	// Open socket
	if( ( sd = openSocket() ) == -1 )
	{
		return SMTP_OC_SOCKET_ERR;
	}
	//Connect to the SMTP server
	if( smtp::connect( sd, smtp_ai->ai_addr, smtp_ai->ai_addrlen, SMTP_TCP_CONNECT_TIMEOUT ) == -1 )
	{
		closeConnection();
		last_err_mssg = string( strerror(errno) );
		if(verbose_flags & SMTP_CONNECTION_DEBUG)
		{
	        evdata.message = "Failed to connect to SMTP server: " + last_err_mssg;
	        evdata.type = SMTP_LIB_FAILED_TO_CONNECT;
	        ei->onEvent(evdata);
		}
		return SMTP_OC_CONN_ERR;
	}
	if(verbose_flags & SMTP_CONNECTION_DEBUG)
	{
	    evdata.message = "Established TCP connection to remote host";
	    evdata.type = SMTP_LIB_DEBUG;
	    ei->onEvent(evdata);
	}
	if( read( sd, rbuffer, sizeof(rbuffer) ) <= 0 )
	{
		fatal_conn_err = true;
		closeConnection();
		last_err_mssg = string( strerror(errno) );
		if(verbose_flags & SMTP_CONNECTION_DEBUG)
		{
	        evdata.message = "Failed to get response from SMTP server: " + last_err_mssg;
	        evdata.type = SMTP_LIB_FAILED_TO_GET_SRV_RESPONSE;
	        ei->onEvent(evdata);
		}
		return SMTP_OC_CONN_ERR;
	}
	if(verbose_flags & SMTP_CONNECTION_DEBUG)
	{
	    evdata.message = "INIT response:\n" + string(rbuffer);
	    evdata.message.erase( evdata.message.size() - 2, 2 ); // remove "\r\n"
	    evdata.type = SMTP_LIB_SMTP_SRV_REPLY;
	    ei->onEvent(evdata);
	}
	// Check INIT code
	if(smtp_code(rbuffer) == SMTP_SERVICE_READY)
	{
		_std_open = true;
	}
	else if(smtp_code(rbuffer) == SMTP_CODE_NO_SMTP)
	{
		closeConnection();
		last_err_mssg = "No SMTP service here";
		if(verbose_flags & SMTP_CONNECTION_DEBUG)
		{
	        evdata.message = "Failed to connect to SMTP server: " + last_err_mssg;
	        evdata.type = SMTP_LIB_FAILED_TO_CONNECT;
	        ei->onEvent(evdata);
		}
		return SMTP_OC_CONN_ERR;
	}
	else
	{
		closeConnection();
		if(verbose_flags & SMTP_CONNECTION_DEBUG)
		{
			last_err_mssg = "SMTP server reply code = " + to_string( smtp_code(rbuffer) );
	        evdata.message = "Failed to connect to SMTP server: " + last_err_mssg;
	        evdata.type = SMTP_LIB_FAILED_TO_CONNECT;
	        ei->onEvent(evdata);
		}
		return SMTP_OC_CONN_ERR;
	}
	// Send EHLO
	if(sendEHLO_std() != SMTP_CODE_OK) // edit error!!!
	{
		abortConnection();
		if(verbose_flags & SMTP_CONNECTION_DEBUG)
		{
	        evdata.message = "Failed to connect to SMTP server: " + last_err_mssg;
	        evdata.type = SMTP_LIB_FAILED_TO_CONNECT;
	        ei->onEvent(evdata);
		}
		return SMTP_OC_CONN_ERR;
	}
	if(verbose_flags & SMTP_CONNECTION_DEBUG)
	{
	    evdata.message = "Successfully connected to SMTP server";
	    evdata.type = SMTP_LIB_DEBUG;
	    ei->onEvent(evdata);
	}
	return SMTP_OC_OK;
}
// Closes connection properly, closes socket
void smtpConnection::closeConnection()
{
	if( !fatal_conn_err and _std_open )
	{
		sendQUIT_std();
	}
	else
	{
		abortConnection();
	}
}
// Aborts connection, closes socket
void smtpConnection::abortConnection()
{
	close(sd);
	_std_open = false;
}
// Tests connection, returns SMTP_OC_* code
int smtpConnection::testConnection()
{
	int rc = openConnection();
	if( rc == SMTP_OC_OK ) closeConnection();
	return rc;
}
// Sends SMTP command, returns response code or error code; returns 0 if connection closed
int smtpConnection::sendCmd(string mssg, bool eod=false)
{
	if(_std_open)
	{
		return sendCmd_std( mssg, eod );
	}
	return 0;
}
// Returns last error message
string smtpConnection::getLastErrMessage() const
{
	return last_err_mssg;
}
#ifdef _ENABLE_TLS_SSL_
// Class 'smtpConnection_TLS' methods
// Constructor
smtpConnection_TLS::smtpConnection_TLS(const struct smtpParams smtpData, uint8_t verbose, eventInformer *eventInf)
                                      :smtpConnection(smtpData, verbose, eventInf), smtpTLS_SSL(verbose, eventInf)
{
	tls = smtpData.tls;
	if( smtpData.port  == to_string(SMTPS_PORT) )
	{
		tls = true;
		start_tls = false;
	}
	else
	{
		start_tls = true;
	}
	if(smtpData.verify)
	{
		setVerification(true, smtpData.srv);
	}
}
// Enables authentication, returns true on success
bool smtpConnection_TLS::enableAuthentication(string username, string password)
{
	if( tls and !username.empty() and !password.empty() )
	{
		_username = username;
		_password = password;
		auth = true;
	}
	else
		auth = false;
	return auth;
}
// Opens SMTPS connection, returns SMTP_OC_* code
int smtpConnection_TLS::openSMTPS()
{
	int rc;
	struct eventData evdata = {SMTP_LIB_CLASS_TLS_CONNECTION, SMTP_LIB_TLSSSL_METHOD_OPEN_SMTPS, "", 0};
	_std_open = false;
	_tls_open = false;

	// Connection setup
	if(!setup)
	{
		if( setupConnection() != 0 ) return SMTP_OC_SETUP_ERR;
	}
	// Open socket
	if( ( sd = openSocket() ) == -1 )
	{
		return SMTP_OC_SOCKET_ERR;
	}
	//Connect to the SMTP server
	if(smtp::connect(sd, smtp_ai->ai_addr, smtp_ai->ai_addrlen, SMTP_TCP_CONNECT_TIMEOUT) == -1)
	{
		closeConnection();
		last_err_mssg = string( strerror(errno) );
		if(verbose_flags & SMTP_CONNECTION_DEBUG)
		{
            evdata.message = "Failed to connect to SMTP server: " + last_err_mssg;
            evdata.type = SMTP_LIB_FAILED_TO_CONNECT;
            ei->onEvent(evdata);
		}
		return SMTP_OC_CONN_ERR;
	}
	// Open TLS/SSL connection
	if( ( rc = connectSSL(sd) ) != SMTP_OC_SSL_OK )
	{
		abortConnection(); // to close socket descriptor
		return rc;
	}
	else if(verbose_flags & SMTP_CONNECTION_DEBUG)
	{
            evdata.message = "TLS/SSL connection established";
            evdata.type = SMTP_LIB_DEBUG;
            ei->onEvent(evdata);
			// coutSrvCerts(); // debug
	}
	// Read SMTP server response
	if( ( rc = readSrvResponse() ) != SMTP_SERVICE_READY )
	{
		if(rc == SMTP_TLS_SSL_READ_ERR)
		{
			closeConnection(false);
			if(verbose_flags & SMTP_CONNECTION_DEBUG)
			{
	            evdata.message = "SMTP server TLS/SSL connection problem: " + last_err_mssg;
	            evdata.type = SMTP_LIB_FAILED_TO_CONNECT;
	            ei->onEvent(evdata);
			}
			return SMTP_OC_TLS_CON_ERR;
		}
		else if(rc == SMTP_CODE_NO_SMTP)
		{
			closeConnection(false);
			if(verbose_flags & SMTP_CONNECTION_DEBUG)
			{
                evdata.message = "Failed to connect to SMTP server: No SMTP service here";
                evdata.type = SMTP_LIB_FAILED_TO_CONNECT;
                ei->onEvent(evdata);
			}
			return SMTP_OC_CONN_ERR;
		}
		else
		{
			closeConnection(false);
			if(verbose_flags & SMTP_CONNECTION_DEBUG)
			{
                evdata.message = "Failed to connect to SMTP server, code = " + to_string(rc);
                evdata.type = SMTP_LIB_FAILED_TO_CONNECT;
                ei->onEvent(evdata);
			}
			return SMTP_OC_CONN_ERR;
		}
	}
	return SMTP_OC_SSL_OK;
}
// Opens connection, returns SMTP_OC_* code
int smtpConnection_TLS::openConnection()
{
	int rc;
	struct eventData evdata = {SMTP_LIB_CLASS_TLS_CONNECTION, SMTP_LIB_TLSSSL_METHOD_OPEN_CONN, "", 0};
	_std_open = false;
	_tls_open = false;

	// Check if TLS/SSL connection requested
	if(!tls)
	{
	    if(verbose_flags & SMTP_CONNECTION_DEBUG)
	    {
	        evdata.message = "TLS/SSL connection NOT requested";
	        evdata.type = SMTP_LIB_DEBUG;
	        ei->onEvent(evdata);
	    }
		return smtpConnection::openConnection();
	}
	if(start_tls)
	{
		if( ( rc = smtpConnection::openConnection() ) != SMTP_OC_OK )
		{
			// connection was not established
			return rc;
		}
		if( !checkEHLOkeyword("STARTTLS") )
		{
			closeConnection();
			last_err_mssg = "SMTP server doesn't support STARTTLS";
			if(verbose_flags & SMTP_CONNECTION_DEBUG)
			{
	            evdata.message = "Failed to start TLS connection: " + last_err_mssg;
	            evdata.type = SMTP_LIB_SSLTLS_CONNECTION_ERROR;
	            ei->onEvent(evdata);
			}
			return SMTP_OC_CONN_ERR;
		}
		else
		{
			if( ( rc = sendCmd_std("STARTTLS") ) != SMTP_SERVICE_READY )
			{
				if(rc > 0)
				{
					closeConnection(true); // SMTP problem
					if(verbose_flags & SMTP_CONNECTION_DEBUG)
					{
		                evdata.message = "Failed to start SMTP connection: " + last_err_mssg;
		                evdata.type = SMTP_LIB_CONNECTION_ERROR;
		                ei->onEvent(evdata);
					}
					return SMTP_OC_CONN_ERR;
				}
				else
				{
					closeConnection(false); // connection problem
					if(verbose_flags & SMTP_CONNECTION_DEBUG)
					{
		                evdata.message = "Failed to connect to SMTP server: " + last_err_mssg;
		                evdata.type = SMTP_LIB_SSLTLS_CONNECTION_ERROR;
		                ei->onEvent(evdata);
					}
					return SMTP_OC_CONN_ERR;
				}
			}
			else
			{
				_std_open = false;
			}
		}
		// Establish SSL connection
		if( ( rc = connectSSL(sd) ) != SMTP_OC_SSL_OK )
		{
			abortConnection(); // to close socket descriptor
			return rc;
		}
		else if(verbose_flags & SMTP_CONNECTION_DEBUG)
		{
            evdata.message = "TLS/SSL connection established";
            evdata.type = SMTP_LIB_DEBUG;
            ei->onEvent(evdata);
			// coutSrvCerts(); // debug
		}
	}
	else
	{
		// Establish SMTPS connection
        if(verbose_flags & SMTP_CONNECTION_DEBUG)
        {
            evdata.message = "SMTPS connection requested";
            evdata.type = SMTP_LIB_DEBUG;
            ei->onEvent(evdata);
        }
		if( ( rc = openSMTPS() ) != SMTP_OC_SSL_OK ) return rc;
	}
	// Send EHLO
    if( ( rc = sendEHLO_tls(host_name) ) != SMTP_CODE_OK )
    {
		closeConnection(false);
		if(verbose_flags & SMTP_CONNECTION_DEBUG)
		{
            evdata.message = "SMTP server connection problem: " + last_err_mssg;
            evdata.type = SMTP_LIB_CONNECTION_ERROR;
            ei->onEvent(evdata);
		}
    	return SMTP_OC_CONN_ERR;
    }
    // Authentication
    if(auth)
    {
  		rc = Authenticate(_username, _password);
   		if(rc != SMTP_CODE_AUTH_OK)
   		{
   			onTLSerror(rc, last_tls_mssg);
   			if( (rc == SMTP_TLS_SSL_READ_ERR) or (rc == SMTP_TLS_SSL_SEND_ERR) ) // Connection read/write error
   			{
   				closeConnection(false);
   				if(verbose_flags & SMTP_CONNECTION_DEBUG)
   				{
   	                evdata.message = "SMTP server connection problem: " + last_err_mssg;
   	                evdata.type = SMTP_LIB_SSLTLS_CONNECTION_ERROR;
   	                ei->onEvent(evdata);
   				}
   		    	return SMTP_OC_TLS_CON_ERR;
   			}
   			closeConnection();
   			if(rc == SMTP_CODE_AUTH_FAILED) // Invalid credentials
   			{
				if(verbose_flags & SMTP_CONNECTION_DEBUG)
				{
		            evdata.message = "SMTP server authentication failed, invalid credentials supplied";
		            evdata.type = SMTP_LIB_SSLTLS_AUTH_FAILED;
		            ei->onEvent(evdata);
				}
   				return SMTP_OC_AUTH_C_ERR;
   			}
   			else if(rc == SMTP_OC_AUTH_M_ERR) // No common authentication method
   			{
				if(verbose_flags & SMTP_CONNECTION_DEBUG)
				{
                    evdata.message = "SMTP server authentication failed, no common authentication method";
                    evdata.type = SMTP_LIB_SSLTLS_AUTH_METHOD_ERROR;
                    ei->onEvent(evdata);
				}
   				return SMTP_OC_AUTH_M_ERR;
   			}
   			else if(rc == SMTP_CODE_AUTH_FAILURE) // Temporary authentication failure
   			{
				if(verbose_flags & SMTP_CONNECTION_DEBUG)
				{
                    evdata.message = "SMTP server authentication failed, temporary authentication failure";
                    evdata.type = SMTP_LIB_SSLTLS_AUTH_FAILED;
                    ei->onEvent(evdata);
				}
   				return SMTP_OC_CONN_ERR;
   			}
   			else // Authentication failure
   			{
				if(verbose_flags & SMTP_CONNECTION_DEBUG)
				{
                    evdata.message = "SMTP server authentication failed, code = " + to_string(rc);
                    evdata.type = SMTP_LIB_SSLTLS_AUTH_FAILED;
                    ei->onEvent(evdata);
				}
   				return SMTP_OC_CONN_ERR;
   			}
   		}
   	}
    else if(verbose_flags & SMTP_CONNECTION_DEBUG)
    {
        evdata.message = "Authentication NOT requested";
        evdata.type = SMTP_LIB_DEBUG;
        ei->onEvent(evdata);
    }
    //
    if(verbose_flags & SMTP_CONNECTION_DEBUG)
    {
        evdata.message = "Successfully connected to SMTP server (TLS/SSL)";
        evdata.type = SMTP_LIB_DEBUG;
        ei->onEvent(evdata);
    }
	return SMTP_OC_SSL_OK;
}
// Sends SMTP command, returns response code or error code; returns 0 if connection closed
int smtpConnection_TLS::sendCmd( string mssg, bool eod)
{
	if(_std_open)
	{
		return sendCmd_std( mssg, eod );
	}
	if(_tls_open)
	{
		return sendCmd_tls( mssg, eod );
	}
	return 0;
}
// Properly closes connection
void smtpConnection_TLS::closeConnection(bool sendQuit)
{
	if(_tls_open)
	{
		if(sendQuit)
		{
			if(closeSSL(true) > 0)
			{
				char rbuffer[SMTP_BUF_SZ];
				(void)!read( sd, rbuffer, sizeof(rbuffer) ); // to finalize TCP connection
				// Note: (void)! is using to avoid translator warning: ‘warn_unused_result’
			}
		}
		else
		{
			closeSSL(false);
		}
	}
	if(sendQuit)
		smtpConnection::closeConnection();
	else
		smtpConnection::abortConnection();
}
// Properly closes connection
void smtpConnection_TLS::closeConnection()
{
	closeConnection(true);
}
// Aborts connection
void smtpConnection_TLS::abortConnection()
{
	abortSSL();
	smtpConnection::abortConnection();
}
// Tests connection, returns SMTP_OC_* code
int smtpConnection_TLS::testConnection()
{
	int rc = openConnection();
	if(rc == 0) closeConnection();
	return rc;
}
// Callback function on TLS/SSL error
void smtpConnection_TLS::onTLSerror(int rc, string error_string)
{
	last_err_mssg = error_string;
}
#endif // _ENABLE_TLS_SSL_

// Class 'protoMailer' methods
// Converts comma delimited string of addresses to vector
vector<string> protoMailer::rcptString2Vector(string addresses)
{
	stringstream ss(addresses);
	vector<string> rcpts;
	string taddr;

	while( ss.good() )
	{
		getline(ss, taddr, ',');
		taddr.erase( remove(taddr.begin(), taddr.end(), ' '), taddr.end() ); // trim spaces
		if( taddr.size() ) rcpts.push_back(taddr);
	}
	return rcpts;
}

// Class 'smtpMailer' methods
// Constructor
smtpMailer::smtpMailer(const struct smtpParams smtpData, uint8_t verbose, eventInformer *eventInf)
{
    verbose_flags = verbose;
    if(eventInf == nullptr)
    {
        self_ei = true;
        ei = new smtpEventInformer();
    }
    else
    {
        self_ei = false;
        ei = eventInf;
    }
    ei->setVerbosityLvl(verbose);
    if(smtpData.tls and !SMTPLIB_BUILD_TLS_SUPPORTED)
    {
        if(verbose_flags & (SMTP_CRITICAL_EVENTS | SMTP_SSL_CONNECTION_DEBUG | SMTP_CONNECTION_DEBUG) )
        {
            struct eventData evdata = {SMTP_LIB_CLASS_MAILER, SMTP_LIB_MAILER_METHOD_CONSTRUCTOR, "", 0};
            evdata.message = "This SMTP library build DOES NOT support SSL/TLS connection";
            evdata.type = SMTP_LIB_TLS_NOT_SUPPORTED;
            ei->onEvent(evdata);
        }
        _run_flag  = false;
        _init_flag = true;
        return;
    }
	smtp_conn = new SMTP_CONNECTION_CLASS(smtpData, verbose, ei);
	_run_flag  = true;
	if( !smtpData.username.empty() and !smtpData.password.empty() )
	{
		smtp_conn->enableAuthentication(smtpData.username, smtpData.password);
	}
	thread mailHandler_thread(&smtpMailer::mailHandler, this);
	mailHandler_thread.detach();
	_init_flag = true;
}
// Destructor
smtpMailer::~smtpMailer()
{
    if(_run_flag)
    {
        _run_flag = false;
        cv_e.notify_all();
        cv_q.notify_all();
        while(!_exit_flag) this_thread::yield(); // waiting for mailHandler to end
        if(smtp_conn != nullptr) delete smtp_conn;
    }
    if(self_ei) delete ei;
}
// Mail sender, returns 0 on successes, error code or number of deferred mails
int smtpMailer::Sender()
{
	int rc, rcpt_cnt, qs;
	struct eventData evdata = {SMTP_LIB_CLASS_MAILER, SMTP_LIB_MAILER_METHOD_SENDER, "", 0};
	bool resend;
	string to_addrs_str;
	postcard pc;
	time_t ctime, stime;
	vector<string> deferred_rcpts;

	if( ( rc = smtp_conn->openConnection() ) == SMTP_OC_OK )
	{
		time(&stime);
		do
		{
			lock(iqmtx, oqmtx);
			while( !inQ.empty() ) // move mails(if available) from input queue to output queue
			{
				pc = inQ.front();
				inQ.pop();
				if(verbose_flags & SMTP_SEND_MAIL_DEBUG)
				{
				    evdata.message = "Get mail";
				    evdata.type = SMTP_LIB_DEBUG;
				    ei->onEvent(evdata);
				}
				outQ.push(pc);
			}
			iqmtx.unlock();
			qs = outQ.size();
			oqmtx.unlock();
			for( uint16_t i = 0; i < qs; ++i )
			{
			    if(verbose_flags & SMTP_SEND_MAIL_DEBUG)
                {
                    evdata.message = "Trying to send mail: " + to_string(i + 1);
                    evdata.type = SMTP_LIB_DEBUG;
                    ei->onEvent(evdata);
                }
				if(_run_flag)
					pc = outQ.front();
				else
					break;
				resend = false;

				// Set sender address
				// RFC-5321 Success: 250; Error: 552, 451, 452, 550, 553, 503, 455, 555, 421, 554
				if( ( rc = smtp_conn->sendCmd( "MAIL FROM:<" + pc.from + ">" ) ) != SMTP_CODE_OK )
				{
					if(rc <= 0)
					{
						// Channel error, abort connection
						smtp_conn->abortConnection();
						if(verbose_flags & SMTP_SEND_MAIL_DEBUG)
						{
	                        evdata.message = "Channel error, connection aborted, code: " + to_string(rc);
	                        evdata.type = SMTP_LIB_CHANNEL_ERROR;
	                        ei->onEvent(evdata);
						}
						return SEND_MAIL_SEND_ERR;
					}
					else if(rc == SMTP_CODE_NO_SERVICE)
					{
						// SMTP server error, abort connection
						smtp_conn->abortConnection();
						if( verbose_flags & SMTP_SEND_MAIL_DEBUG )
						{
	                        evdata.message = "SMTP server error, connection aborted, code: " + to_string(rc);
	                        evdata.type = SMTP_LIB_SERVER_ERROR;
	                        ei->onEvent(evdata);
						}
						return SEND_MAIL_SEND_ERR;
					}
					else if(rc == SMTP_CODE_SYNTAX_ERR)
					{
						// Sender address invalid, drop mail
						++stats.drp_mail_cnt;
						if(verbose_flags & SMTP_SEND_MAIL_DEBUG)
						{
	                        evdata.message = "Sender address invalid, mail dropped, code: " + to_string(rc);
	                        evdata.type = SMTP_LIB_SENDER_ADDR_INVALID;
	                        ei->onEvent(evdata);
						}
						onSendEvent(pc, SEND_MAIL_ACT_DROP, pc.from, rc, "Sender address invalid");
					}
					else if(rc == SMTP_CODE_NO_MAILBOX)
					{
						// Sender unknown or not valid, drop mail
						++stats.drp_mail_cnt;
						if(verbose_flags & SMTP_SEND_MAIL_DEBUG)
						{
	                        evdata.message = "Sender address unknown or not valid, mail dropped, code: " + to_string(rc);
	                        evdata.type = SMTP_LIB_SENDER_ADDR_UNKNOWN;
	                        ei->onEvent(evdata);
						}
						onSendEvent(pc, SEND_MAIL_ACT_DROP, pc.from, rc, "Sender address unknown or not valid");
					}
					else if(rc == SMTP_CODE_NOT_ALLOWED)
					{
						// Sender address not allowed, drop mail
						++stats.drp_mail_cnt;
						if(verbose_flags & SMTP_SEND_MAIL_DEBUG)
						{
	                        evdata.message = "Sender address not allowed, mail dropped, code: " + to_string(rc);
	                        evdata.type = SMTP_LIB_SENDER_ADDR_UNALLOWED;
	                        ei->onEvent(evdata);
						}
						onSendEvent(pc, SEND_MAIL_ACT_DROP, pc.from, rc, "Sender address not allowed");
					}
					else if(rc == SMTP_CODE_PARAM_ERR)
					{
						// Sender address invalid, drop mail
						++stats.drp_mail_cnt;
						if(verbose_flags & SMTP_SEND_MAIL_DEBUG)
						{
	                        evdata.message = "Sender address invalid, mail dropped, code: " + to_string(rc);
	                        evdata.type = SMTP_LIB_SENDER_ADDR_INVALID;
	                        ei->onEvent(evdata);
						}
						onSendEvent(pc, SEND_MAIL_ACT_DROP, pc.from, rc, "Sender address invalid");
					}
					else if(rc == SMTP_CODE_FWD_ERR)
					{
						// Sender address is not valid for your login, drop mail
						++stats.drp_mail_cnt;
						if(verbose_flags & SMTP_SEND_MAIL_DEBUG)
						{
	                        evdata.message = "Sender address is not valid for your login, mail dropped, code: " + to_string(rc);
	                        evdata.type = SMTP_LIB_SENDER_ADDR_INVALID_FOR_LOGIN;
	                        ei->onEvent(evdata);
						}
						onSendEvent(pc, SEND_MAIL_ACT_DROP, pc.from, rc, "Sender address is not valid for your login");
					}
					else if(rc == SMTP_CODE_NOT_ACCEPTED)
					{
						// Sender address was not accepted by SMTP server, drop mail
						++stats.drp_mail_cnt;
						if(verbose_flags & SMTP_SEND_MAIL_DEBUG)
						{
	                        evdata.message = "Sender address was not accepted by SMTP server, mail dropped, code: " + to_string(rc);
	                        evdata.type = SMTP_LIB_SENDER_ADDR_NOT_ACCEPTED;
	                        ei->onEvent(evdata);
						}
						onSendEvent(pc, SEND_MAIL_ACT_DROP, pc.from, rc, "Sender address was not accepted by SMTP server");
					}
					else
					{
						// Possibly recoverable error, will try to resend later
						if(verbose_flags & SMTP_SEND_MAIL_DEBUG)
						{
	                        evdata.message = "Sender address error, will try to resend later, code: " + to_string(rc);
	                        evdata.type = SMTP_LIB_SENDER_ADDR_ERROR;
	                        ei->onEvent(evdata);
						}
						onSendEvent(pc, SEND_MAIL_ACT_WAIT, pc.from, rc, "Sender address error");
						resend = true;
					}
				}
				else
				{
					// Clear deferred recipients vector
					deferred_rcpts.clear();
					rcpt_cnt = 0;
					// Process recipient addresses
					to_addrs_str = "";
					for( string taddr: pc.to )
					{
						// Set recipient address
						// RFC-5321 Success: 250, 251; Error: 550, 551, 552, 553, 450, 451, 452, 503, 455, 555, 554
						rc = smtp_conn->sendCmd( "RCPT TO:<" + taddr + ">" );
						if( (rc != SMTP_CODE_OK) and (rc != SMTP_CODE_OK_FWD) )
						{
							if(rc <= 0)
							{
								// Channel error, abort connection
								smtp_conn->abortConnection();
								if(verbose_flags & SMTP_SEND_MAIL_DEBUG)
								{
	                                evdata.message = "Channel error, connection aborted, code: " + to_string(rc);
	                                evdata.type = SMTP_LIB_CHANNEL_ERROR;
	                                ei->onEvent(evdata);
								}
								return SEND_MAIL_SEND_ERR;
							}
							else if(rc == SMTP_CODE_NO_SERVICE)
							{
								// SMTP server error, abort connection
								smtp_conn->abortConnection();
								if( verbose_flags & SMTP_SEND_MAIL_DEBUG )
								{
	                                evdata.message = "SMTP server error, connection aborted, code: " + to_string(rc);
	                                evdata.type = SMTP_LIB_SERVER_ERROR;
	                                ei->onEvent(evdata);
								}
								return SEND_MAIL_SEND_ERR;
							}
							else if(rc == SMTP_CODE_SYNTAX_ERR)
							{
								// Recipient address invalid
								if(verbose_flags & SMTP_SEND_MAIL_DEBUG)
								{
	                                evdata.message = "Mailbox <" + taddr + "> syntax error, rejected, code: " + to_string(rc);
	                                evdata.type = SMTP_LIB_MB_SYNTAX_ERROR;
	                                ei->onEvent(evdata);
								}
								onSendEvent(pc, SEND_MAIL_ACT_RJCT, taddr, rc, "Mailbox <" + taddr + "> syntax error");
							}
							else if(rc == SMTP_CODE_NO_MAILBOX)
							{
								// Recipient mailbox unknown or not valid
								if(verbose_flags & SMTP_SEND_MAIL_DEBUG)
								{
	                                evdata.message = "Mailbox <" + taddr + "> unavailable, rejected, code: " + to_string(rc);
	                                evdata.type = SMTP_LIB_MB_UNAVAILABLE;
	                                ei->onEvent(evdata);
								}
								onSendEvent(pc, SEND_MAIL_ACT_RJCT, taddr, rc, "Mailbox <" + taddr + "> unavailable");
							}
							else if(rc == SMTP_CODE_NOT_ALLOWED)
							{
								// Recipient address not allowed
								if(verbose_flags & SMTP_SEND_MAIL_DEBUG)
								{
	                                evdata.message = "Mailbox <" + taddr + "> not allowed, rejected, code: " + to_string(rc);
	                                evdata.type = SMTP_LIB_MB_NOT_ALLOWED;
	                                ei->onEvent(evdata);
								}
								onSendEvent(pc, SEND_MAIL_ACT_RJCT, taddr, rc, "Mailbox <" + taddr + "> not allowed");
							}
							else if(rc == SMTP_CODE_PARAM_ERR)
							{
								// Recipient address invalid
								if(verbose_flags & SMTP_SEND_MAIL_DEBUG)
								{
	                                evdata.message = "Mailbox <" + taddr + "> invalid, rejected, code: " + to_string(rc);
	                                evdata.type = SMTP_LIB_MB_INVALID;
	                                ei->onEvent(evdata);
								}
								onSendEvent(pc, SEND_MAIL_ACT_RJCT, taddr, rc, "Mailbox <" + taddr + "> invalid");
							}
							else if(rc == SMTP_CODE_FWD_ERR)
							{
								// Unable to forward
								if(verbose_flags & SMTP_SEND_MAIL_DEBUG)
								{
	                                evdata.message = "Unable to forward to <" + taddr + ">, rejected, code: " + to_string(rc);
	                                evdata.type = SMTP_LIB_UNABLE_FRWD;
	                                ei->onEvent(evdata);
								}
								onSendEvent(pc, SEND_MAIL_ACT_RJCT, taddr, rc, "Unable to forward to <" + taddr + ">");
							}
							else if(rc == SMTP_CODE_NOT_ACCEPTED)
							{
								// Recipient address was not accepted by SMTP server
								if(verbose_flags & SMTP_SEND_MAIL_DEBUG)
								{
	                                evdata.message = "Recipient <" + taddr + "> was not accepted by SMTP server, rejected, code: " + to_string(rc);
	                                evdata.type = SMTP_LIB_RCPNT_NOT_ACCEPTED;
	                                ei->onEvent(evdata);
								}
								onSendEvent(pc, SEND_MAIL_ACT_RJCT, taddr, rc, "Recipient <" + taddr + "> was not accepted by SMTP server");
							}
							else
							{
								// Possibly recoverable error, will try to resend later
								if(verbose_flags & SMTP_SEND_MAIL_DEBUG)
								{
	                                evdata.message = "Recipient <" + taddr + "> address error, will try to resend later, code: " + to_string(rc);
	                                evdata.type = SMTP_LIB_RCPNT_ADDR_ERROR;
	                                ei->onEvent(evdata);
								}
								onSendEvent(pc, SEND_MAIL_ACT_WAIT, taddr, rc, "Recipient address error");
								// Add to deferred recipients vector
								deferred_rcpts.push_back(taddr);
							}
						}
						else
						{
							++rcpt_cnt;
							to_addrs_str += taddr + ",";
						}
					}
					if(rcpt_cnt == 0)
					{
						// No valid recipients
						time(&ctime);
						if( deferred_rcpts.empty() )
						{
							// No deferred recipients, drop mail
							++stats.drp_mail_cnt;
							if(verbose_flags & SMTP_SEND_MAIL_DEBUG)
							{
	                            evdata.message = "No valid recipients, mail dropped";
	                            evdata.type = SMTP_LIB_NO_VALID_RCPNTS;
	                            ei->onEvent(evdata);
							}
							onSendEvent(pc, SEND_MAIL_ACT_DROP, "", 0, "No valid recipients");
						}
						else if( ctime > (pc.timestamp + rlimits.resend_tw) )
						{
							// Resend timeout exceeded, drop mail
							++stats.drp_mail_cnt;
							if(verbose_flags & SMTP_SEND_MAIL_DEBUG)
							{
	                            evdata.message = "Resend timeout exceeded, mail dropped";
	                            evdata.type = SMTP_LIB_RESEND_TIMEOUT_EXCEEDED;
	                            ei->onEvent(evdata);
							}
							onSendEvent(pc, SEND_MAIL_ACT_DROP, "", 0, "Resend timeout exceeded");
						}
						else
						{
							// Requeue mail with deferred recipients
							defQ.push( {pc.from, deferred_rcpts, pc.subj, pc.message, pc.type, pc.timestamp} );
						}
					}
					else
					{
						// Start data transmission
						// RFC-5321 Success: 354; Error: 503, 554
						if( ( rc = smtp_conn->sendCmd("DATA") ) != SMTP_CODE_START_MAIL )
						{
							if(rc <= 0)
							{
								// Channel error, abort connection
								smtp_conn->abortConnection();
								if(verbose_flags & SMTP_SEND_MAIL_DEBUG)
								{
	                                evdata.message = "Channel error, connection aborted, code: " + to_string(rc);
	                                evdata.type = SMTP_LIB_CHANNEL_ERROR;
	                                ei->onEvent(evdata);
								}
								return SEND_MAIL_SEND_ERR;
							}
							else if(rc == SMTP_CODE_NO_SERVICE)
							{
								// SMTP server error, abort connection
								smtp_conn->abortConnection();
								if(verbose_flags & SMTP_SEND_MAIL_DEBUG)
								{
	                                evdata.message = "SMTP server error, connection aborted, code: " + to_string(rc);
	                                evdata.type = SMTP_LIB_SERVER_ERROR;
	                                ei->onEvent(evdata);
								}
								return SEND_MAIL_SEND_ERR;
							}
							else
							{
								// Possibly recoverable error, will try to resend later
								if(verbose_flags & SMTP_SEND_MAIL_DEBUG)
								{
	                                evdata.message = "Start data transmission error, will try to resend later, code: " + to_string(rc);
	                                evdata.type = SMTP_LIB_TRANSMISSION_ERROR;
	                                ei->onEvent(evdata);
								}
								onSendEvent(pc, SEND_MAIL_ACT_WAIT, "", rc, "Start data transmission error");
								resend = true;
							}
						}
						else
						{
							to_addrs_str.pop_back(); // remove ending comma
							// Data transmission
							// RFC-5321 Success: 250; Error: 552, 554, 451, 452 and 450, 550 (rejections for policy reasons)
							rc = smtp_conn->sendCmd( emailForm( pc.from, to_addrs_str , pc.subj, pc.message ), true );
							if(rc != SMTP_CODE_OK)
							{
								if(rc <= 0)
								{
									// Channel error, abort connection
									smtp_conn->abortConnection();
									if(verbose_flags & SMTP_SEND_MAIL_DEBUG)
									{
	                                    evdata.message = "Channel error, connection aborted, code: " + to_string(rc);
	                                    evdata.type = SMTP_LIB_CHANNEL_ERROR;
	                                    ei->onEvent(evdata);
									}
									return SEND_MAIL_SEND_ERR;
								}
								else if(rc == SMTP_CODE_NO_SERVICE)
								{
									// SMTP server error, abort connection
									smtp_conn->abortConnection();
									if( verbose_flags & SMTP_SEND_MAIL_DEBUG )
									{
	                                    evdata.message = "SMTP server error, connection aborted, code: " + to_string(rc);
	                                    evdata.type = SMTP_LIB_SERVER_ERROR;
	                                    ei->onEvent(evdata);
									}
									return SEND_MAIL_SEND_ERR;
								}
								else
								{
									// Possibly recoverable error, will try to resend later
									if(verbose_flags & SMTP_SEND_MAIL_DEBUG)
									{
	                                    evdata.message = "Data transmission error, will try to resend later, code: " + to_string(rc);
	                                    evdata.type = SMTP_LIB_TRANSMISSION_ERROR;
	                                    ei->onEvent(evdata);
									}
									onSendEvent(pc, SEND_MAIL_ACT_WAIT, "", rc, "Data transmission error");
									resend = true;
								}
							}
							else
							{
								// Successfully sent
								++stats.sent_cnt;
								if(verbose_flags & SMTP_SEND_MAIL_DEBUG)
								{
	                                evdata.message = "Successfully sent mail, code: " + to_string(rc);
	                                evdata.type = SMTP_LIB_SENT_OK;
	                                ei->onEvent(evdata);
								}
								onSendEvent(pc, SEND_MAIL_ACT_SENT, "", rc, "Successfully sent mail");
								// Requeue mail with deferred recipients if any
								if( not deferred_rcpts.empty() )
								{
									time(&ctime);
									if( ctime > (pc.timestamp + rlimits.resend_tw) )
									{
										// Resend timeout exceeded, drop mail
										++stats.drp_mail_cnt;
										if(verbose_flags & SMTP_SEND_MAIL_DEBUG)
										{
	                                        evdata.message = "Resend timeout exceeded, mail dropped";
	                                        evdata.type = SMTP_LIB_RESEND_TIMEOUT_EXCEEDED;
	                                        ei->onEvent(evdata);
										}
										onSendEvent(pc, SEND_MAIL_ACT_DROP, "", 0, "Resend timeout exceeded");
									}
									else
									{
										// Requeue mail with deferred recipients
										defQ.push( {pc.from, deferred_rcpts, pc.subj, pc.message, pc.type, pc.timestamp} );
									}
								}
							}
						}
					}
				}
				// Remove current mail from queue
				oqmtx.lock();
				outQ.pop();
				oqmtx.unlock();
				// Requeue if necessary
				if(resend)
				{
					time(&ctime);
					if( ctime > (pc.timestamp + rlimits.resend_tw) )
					{
						// Resend timeout exceeded, drop mail
						++stats.drp_mail_cnt;
						if(verbose_flags & SMTP_SEND_MAIL_DEBUG)
						{
	                        evdata.message = "Resend timeout exceeded, mail dropped";
	                        evdata.type = SMTP_LIB_RESEND_TIMEOUT_EXCEEDED;
	                        ei->onEvent(evdata);
						}
						onSendEvent(pc, SEND_MAIL_ACT_DROP, "", 0, "Resend timeout exceeded");
					}
					else
					{
						// Requeue
						defQ.push(pc);
					}
				}
				// Reset parameters for new mail processing
				if( ( rc = smtp_conn->sendCmd("RSET") ) != SMTP_CODE_OK )
				{
					if(rc <= 0)
					{
						// Channel error, abort connection
						smtp_conn->abortConnection();
						if(verbose_flags & SMTP_SEND_MAIL_DEBUG)
						{
	                        evdata.message = "Channel error, connection aborted, code: " + to_string(rc);
	                        evdata.type = SMTP_LIB_CHANNEL_ERROR;
	                        ei->onEvent(evdata);
						}
						return SEND_MAIL_SEND_ERR;
					}
					else if(rc == SMTP_CODE_NO_SERVICE)
					{
						// SMTP server error, abort connection
						smtp_conn->abortConnection();
						if(verbose_flags & SMTP_SEND_MAIL_DEBUG)
						{
	                        evdata.message = "SMTP server error, connection aborted, code: " + to_string(rc);
	                        evdata.type = SMTP_LIB_SERVER_ERROR;
	                        ei->onEvent(evdata);
						}
						return SEND_MAIL_SEND_ERR;
					}
					else
					{
						// Unknown error
						smtp_conn->closeConnection();
						if(verbose_flags & SMTP_SEND_MAIL_DEBUG)
						{
	                        evdata.message = "Reset error, connection closed, code: " + to_string(rc);
	                        evdata.type = SMTP_LIB_RESET_ERROR;
	                        ei->onEvent(evdata);
						}
						return SEND_MAIL_SEND_ERR;
					}
				} // end if
			} // end for
			if(_run_flag) this_thread::sleep_for(1s);
			time(&ctime);
		} while( _run_flag and ( ctime <= (stime + MAIL_SENDER_CONNECTION_TIME) ) ); // end do
	}
	else
	{
		if(verbose_flags & SMTP_SEND_MAIL_DEBUG)
		{
	        evdata.message = "Failed to connect to SMTP server, code: " + to_string(rc);
	        evdata.type = SMTP_LIB_FAILED_TO_CONNECT;
	        ei->onEvent(evdata);
		}
		return rc;
	}
	smtp_conn->closeConnection();
	return defQ.size();
}
// Mail handler
void smtpMailer::mailHandler()
{
	int rc;
	string subj, mssg, faddr, info_mssg;
	vector<string> taddrs;
	struct eventData evdata = {SMTP_LIB_CLASS_MAILER, SMTP_LIB_MAILER_METHOD_HANDLER, "", 0};
	struct postcard pc;
	const seconds idle_time = MAIL_HANDLER_IDLE_TIME, base_retry_time = MAIL_HANDLER_BASE_RETRY_TIME;
	seconds retry_time;
	uint32_t ec = 0;
	steady_time_point_t ctime;
	struct {
	    steady_time_point_t setup_err;
	    steady_time_point_t socket_err;
	    steady_time_point_t oc_err;
	    steady_time_point_t tls_sys_err;
	    steady_time_point_t tls_con_err;
	    steady_time_point_t tls_vrf_err;
	    steady_time_point_t auth_m_err;
	    steady_time_point_t auth_c_err;
	    steady_time_point_t send_err;
	} err_start = {};

	unique_lock<mutex> iqlck(iqmtx);

	while(_run_flag)
	{
		while( _run_flag and ( !inQ.empty() or !outQ.empty() ) )
		{
			if(_run_flag and _enable_flag)
			{
				iqlck.unlock();
				rc = Sender();
				oqmtx.lock();
				while( _run_flag and !defQ.empty() ) // move mails(if available) from deferred queue to output queue
				{
					pc = defQ.front();
					defQ.pop();
					outQ.push(pc);
				}
				oqmtx.unlock();
				if(rc >= 0)
				{
					// no errors, clear error counters
					err_count.clear();
					ec = 0;
					retry_time = idle_time;
				}
				else
				{
					++stats.conn_err_cnt; // increment connection error counter
					retry_time = base_retry_time * ( (++ec < 16) ? ( 1 << (ec - 1) ) : (1 << 16) );
					retry_time = min(retry_time, idle_time);
				}
				if( _run_flag and (rc != SEND_MAIL_OK) )
				{
				    ctime = chrono::steady_clock::now();
					switch(rc)
					{
						case SEND_MAIL_SETUP_ERR:
							if(err_count.setup_err == 0) err_start.setup_err = ctime;
							onSendError( rc, ++err_count.setup_err, elapsed_time(ctime, err_start.setup_err),
							            smtp_conn->getLastErrMessage() );
							break;
						case SEND_MAIL_SOCKET_ERR:
							err_count.setup_err = 0; // setup - OK
							if(err_count.socket_err == 0) err_start.socket_err = ctime;
							onSendError( rc, ++err_count.socket_err, elapsed_time(ctime, err_start.socket_err),
							            smtp_conn->getLastErrMessage() );
							break;
						case SEND_MAIL_CONN_ERR:
							err_count.setup_err  = 0; // setup - OK
							err_count.socket_err = 0; // socket - OK
							if(err_count.oc_err == 0) err_start.oc_err = ctime;
							onSendError( rc, ++err_count.oc_err, elapsed_time(ctime, err_start.oc_err),
							            smtp_conn->getLastErrMessage() );
							break;
						case SEND_MAIL_TLS_SYS_ERR:
							err_count.setup_err  = 0; // setup - OK
							err_count.socket_err = 0; // socket - OK
							err_count.oc_err     = 0; // open connection - OK
							if(err_count.tls_sys_err == 0) err_start.tls_sys_err = ctime;
							onSendError( rc, ++err_count.tls_sys_err, elapsed_time(ctime, err_start.tls_sys_err),
							            smtp_conn->getLastErrMessage() );
							break;
						case SEND_MAIL_TLS_CON_ERR:
							err_count.setup_err   = 0; // setup - OK
							err_count.socket_err  = 0; // socket - OK
							err_count.oc_err      = 0; // open connection - OK
							err_count.tls_sys_err = 0; // TLS environment - OK
							if(err_count.tls_con_err == 0) err_start.tls_con_err = ctime;
							onSendError( rc, ++err_count.tls_con_err, elapsed_time(ctime, err_start.tls_con_err),
							            smtp_conn->getLastErrMessage() );
							break;
						case SEND_MAIL_TLS_VRF_ERR:
							err_count.setup_err   = 0; // setup - OK
							err_count.socket_err  = 0; // socket - OK
							err_count.oc_err      = 0; // open connection - OK
							err_count.tls_sys_err = 0; // TLS environment - OK
							err_count.tls_con_err = 0; // SSL connection - OK
							if(err_count.tls_vrf_err == 0) err_start.tls_vrf_err = ctime;
							onSendError( rc, ++err_count.tls_vrf_err, elapsed_time(ctime, err_start.tls_vrf_err),
							            smtp_conn->getLastErrMessage() );
							break;
						case SEND_MAIL_AUTH_M_ERR:
							err_count.setup_err   = 0; // setup - OK
							err_count.socket_err  = 0; // socket - OK
							err_count.oc_err      = 0; // open connection - OK
							err_count.tls_sys_err = 0; // TLS environment - OK
							err_count.tls_con_err = 0; // SSL connection - OK
							err_count.tls_vrf_err = 0; // SSL certificate - OK
							if(err_count.auth_m_err == 0) err_start.auth_m_err = ctime;
							onSendError( rc, ++err_count.auth_m_err, elapsed_time(ctime, err_start.auth_m_err),
							        smtp_conn->getLastErrMessage() );
							break;
						case SEND_MAIL_AUTH_C_ERR:
							err_count.setup_err   = 0; // setup - OK
							err_count.socket_err  = 0; // socket - OK
							err_count.oc_err      = 0; // open connection - OK
							err_count.tls_sys_err = 0; // TLS environment - OK
							err_count.tls_con_err = 0; // SSL connection - OK
							err_count.tls_vrf_err = 0; // SSL certificate - OK
							err_count.auth_m_err  = 0; // Authentication method - OK
							if(err_count.auth_c_err == 0) err_start.auth_c_err = ctime;
							onSendError( rc, ++err_count.auth_c_err, elapsed_time(ctime, err_start.auth_c_err),
							            smtp_conn->getLastErrMessage() );
							break;
						case SEND_MAIL_SEND_ERR:
							err_count.setup_err   = 0; // setup - OK
							err_count.socket_err  = 0; // socket - OK
							err_count.oc_err      = 0; // open connection - OK
							err_count.tls_sys_err = 0; // TLS environment - OK
							err_count.tls_con_err = 0; // SSL connection - OK
							err_count.tls_vrf_err = 0; // SSL certificate - OK
							err_count.auth_m_err  = 0; // Authentication method - OK
							err_count.auth_c_err  = 0; // Authentication - OK
							if(err_count.send_err == 0) err_start.send_err = ctime;
							onSendError( rc, ++err_count.send_err, elapsed_time(ctime, err_start.send_err),
							            smtp_conn->getLastErrMessage() );
							break;
					} // end switch
					if(_run_flag and _enable_flag)
					{
						unique_lock<mutex> elck(emtx); // for 'cv_s.wait_for' functionality only
						cv_e.wait_for(elck, retry_time);
					}
				} // end if error
				iqlck.lock();
			} // end if sender
			else
			{
				break;
			}
		} // end while Q
		if(_run_flag)
		{
			cv_q.wait_for(iqlck, idle_time);
		}
		else
		{
			iqlck.unlock();
			break;
		}
	} // end while main
	if(verbose_flags & SMTP_MAIL_HANDLER_STOPPED)
	{
	    evdata.message = "Service 'mailHandler' stopped";
	    evdata.type = SMTP_LIB_HANDLER_STOPPED;
	    ei->onEvent(evdata);
	}
	_exit_flag = true;
	return;
}
// Creates email message in standard format (RFC 5322)
string smtpMailer::emailForm(string from_addr, string to_addr, string subj, string txt)
{
	const string crlf = "\r\n";
	string mssg = "MIME-Version 1.0" + crlf;

	mssg  = "Date: " + getLocalTimeSMTP() + crlf;
	mssg += "To: " + to_addr + crlf;
	mssg += "From: " + from_addr + crlf;
	mssg += "Subject: " + subj + crlf;
	mssg += "X-Mailer: " + string(SMTP_CLIENT_NAME) + crlf;
	mssg += "Content-Type: text/plain; charset=\"UTF-8\"" + crlf;
	mssg += "Content-Transfer-Encoding: 7bit" + crlf;
	mssg += replaceLFwithCRLF(txt); // all newlines MUST be CRLF

	return mssg;
}
// Returns true if smtpMailer is started
bool smtpMailer::isStarted() const
{
	return (_init_flag and _run_flag);
}
// Returns true if mail processing is on
bool smtpMailer::isEnabled() const
{
	return _enable_flag;
}
// Enables or disables mail processing
void smtpMailer::setState(bool state)
{
	if(_enable_flag)
	{
		if(!state) _enable_flag = false; // disable mail processing
	}
	else if(state)
	{
		// clear error counters
		err_count.clear();
		// enable mail processing
		_enable_flag = true;
	}
}
// Returns input queue length (thread safe)
size_t smtpMailer::inQueueSize()
{
	unique_lock<mutex> qlck(iqmtx);
	return inQ.size();
}
// Returns output queue length (thread safe)
size_t smtpMailer::outQueueSize()
{
	unique_lock<mutex> qlck(oqmtx);
	return outQ.size();
}
// Tests connection to SMTP server, return 0 on success or error code
int smtpMailer::testConnection()
{
	return smtp_conn->testConnection();
}
// Sends mail, returns 0 on success, -1 if sender string empty, -2 if recipients string empty
int smtpMailer::sendMail(string sender, vector<string> recipients, string subj, string mssg, char type)
{
    const struct eventData evdata = {SMTP_LIB_CLASS_MAILER, SMTP_LIB_MAILER_METHOD_SENDMAIL, "New mail in inbox", SMTP_LIB_DEBUG};
	time_t ts;

	if( sender.empty() )
	{
		return -1;
	}
	else
	{
		sender.erase( remove( sender.begin(), sender.end(), ' ' ), sender.end() ); // trim spaces
	}
	if( recipients.empty() )
	{
		return -2;
	}
	time(&ts);
	iqmtx.lock();
	if(_run_flag)
	{
		inQ.push( {sender, recipients, subj, mssg, type, ts} );
	}
	iqmtx.unlock();
    if(verbose_flags & SMTP_SEND_MAIL_DEBUG)
    {
        ei->onEvent(evdata);
    }
	cv_q.notify_one();
	return 0;
}
// Sends mail, returns 0 on success, -1 if sender string empty, -2 if recipients vector empty
int smtpMailer::sendMail(string sender, string recipients, string subj, string mssg, char type)
{
	vector<string> rcpts;

	if( recipients.empty() )
	{
		return -2;
	}
	else
	{
		rcpts = rcptString2Vector(recipients);
	}
	return sendMail( sender, rcpts, subj, mssg, type );
}
// Callback function on send errors
void smtpMailer::onSendError(int rc, uint32_t err_cnt, seconds err_duration, string message)
{
    struct eventData evdata = {SMTP_LIB_CLASS_MAILER, SMTP_LIB_MAILER_METHOD_ONSENDERROR, "", 0};

	switch(rc)
	{
		case SEND_MAIL_SETUP_ERR:
			if(err_duration >= rlimits.setup_tw)
			{
				setState(false);
				if( verbose_flags & (SMTP_MAIL_HANDLER_DEBUG | SMTP_CRITICAL_EVENTS) )
				{
	                evdata.type = SMTP_LIB_CONNECTION_SETUP_ERROR;
	                evdata.message = "SMTP server setup error: " + message;
	                ei->onEvent(evdata);
	                evdata.message = "Connection setup timeout exceeded, SMTP client service was stopped";
	                ei->onEvent(evdata);
				}
			}
			else if(verbose_flags & SMTP_MAIL_HANDLER_DEBUG)
			{
                evdata.message = "Attempt: " + to_string(err_cnt) + ", SMTP server setup error: " + message;
                evdata.type = SMTP_LIB_CONNECTION_SETUP_ERROR;
                ei->onEvent(evdata);
			}
			break;
		case SEND_MAIL_SOCKET_ERR:
			if(err_cnt >= rlimits.socket)
			{
				setState(false);
				if( verbose_flags & (SMTP_MAIL_HANDLER_DEBUG | SMTP_CRITICAL_EVENTS) )
				{
					evdata.type = SMTP_LIB_SOCKET_ERROR;
	                evdata.message = "System error: " + message;
	                ei->onEvent(evdata);
	                evdata.message = "Unable to open socket, SMTP client service was stopped";
	                ei->onEvent(evdata);
				}
			}
			else if(verbose_flags & SMTP_MAIL_HANDLER_DEBUG)
			{
                evdata.message  = "Attempt: " + to_string(err_cnt) + ", Open socket error: " + message;
                evdata.type = SMTP_LIB_SOCKET_ERROR;
                ei->onEvent(evdata);
			}
			break;
		case SEND_MAIL_CONN_ERR:
			if(err_duration >= rlimits.connect_tw)
			{
				setState(false);
				if( verbose_flags & (SMTP_MAIL_HANDLER_DEBUG | SMTP_CRITICAL_EVENTS) )
				{
					evdata.type = SMTP_LIB_CONNECTION_ERROR;
	                evdata.message = "Failed to connect to SMTP server: " + message;
	                ei->onEvent(evdata);
	                evdata.message = "Connection timeout exceeded, SMTP client service was stopped";
	                ei->onEvent(evdata);
				}
			}
			else if(verbose_flags & SMTP_MAIL_HANDLER_DEBUG)
			{
                evdata.message = "Attempt: " + to_string(err_cnt) + ", Failed to connect to SMTP server: " + message;
                evdata.type = SMTP_LIB_CONNECTION_ERROR;
                ei->onEvent(evdata);
			}
			break;
		case SEND_MAIL_TLS_SYS_ERR:
			if(err_cnt >= rlimits.tls_sys)
			{
				setState(false);
				if( verbose_flags & (SMTP_MAIL_HANDLER_DEBUG | SMTP_CRITICAL_EVENTS) )
				{
                    evdata.type = SMTP_LIB_SSLTLS_SETUP_ERROR;
	                evdata.message = "SSL/TLS system error: " + message;
                    ei->onEvent(evdata);
	                evdata.message = "Unable to setup SSL/TLS environment, SMTP client service was stopped";
	                ei->onEvent(evdata);
				}
			}
			else if(verbose_flags & SMTP_MAIL_HANDLER_DEBUG)
			{
                evdata.message = "Attempt: " + to_string(err_cnt) + ", Failed to setup SSL/TLS environment: " + message;
                evdata.type = SMTP_LIB_SSLTLS_SETUP_ERROR;
                ei->onEvent(evdata);
			}
			break;
		case SEND_MAIL_TLS_CON_ERR:
			if(err_cnt >= rlimits.tls_con)
			{
				setState(false);
				if( verbose_flags & (SMTP_MAIL_HANDLER_DEBUG | SMTP_CRITICAL_EVENTS) )
				{
                    evdata.type = SMTP_LIB_SSLTLS_CONNECTION_ERROR;
                    evdata.message = "SSL/TLS connection error: " + message;
                    ei->onEvent(evdata);
                    evdata.message = "Unable to establish SSL/TLS connection, SMTP client service was stopped";
	                ei->onEvent(evdata);
				}
			}
			else if(verbose_flags & SMTP_MAIL_HANDLER_DEBUG)
			{
                evdata.message = "Attempt: " + to_string(err_cnt) + ", Failed to establish SSL/TLS connection: " + message;
                evdata.type = SMTP_LIB_SSLTLS_CONNECTION_ERROR;
                ei->onEvent(evdata);
			}
			break;
		case SEND_MAIL_TLS_VRF_ERR:
			if(err_cnt >= rlimits.tls_vrf)
			{
				setState(false);
				if( verbose_flags & (SMTP_MAIL_HANDLER_DEBUG | SMTP_CRITICAL_EVENTS) )
				{
                    evdata.type = SMTP_LIB_SSLTLS_SRV_VERIFICATION_ERROR;
	                evdata.message = "SSL verification error: " + message;
	                ei->onEvent(evdata);
	                evdata.message = "Unable to verify SMTP server certificate, SMTP client service was stopped";
	                ei->onEvent(evdata);
				}
			}
			else if(verbose_flags & SMTP_MAIL_HANDLER_DEBUG)
			{
                evdata.message = "Attempt: " + to_string(err_cnt) + ", Failed to verify SMTP server certificate: " + message;
                evdata.type = SMTP_LIB_SSLTLS_SRV_VERIFICATION_ERROR;
                ei->onEvent(evdata);
			}
			break;
		case SEND_MAIL_AUTH_M_ERR:
			if(err_cnt >= rlimits.auth_m)
			{
				setState(false);
				if( verbose_flags & (SMTP_MAIL_HANDLER_DEBUG | SMTP_CRITICAL_EVENTS) )
				{
                    evdata.type = SMTP_LIB_SSLTLS_AUTH_METHOD_ERROR;
	                evdata.message = "Authentication error: " + message;
	                ei->onEvent(evdata);
	                evdata.message = "Authentication error, SMTP client service was stopped";
	                ei->onEvent(evdata);
				}
			}
			else if(verbose_flags & SMTP_MAIL_HANDLER_DEBUG)
			{
                evdata.message = "Attempt: " + to_string(err_cnt) + ", Authentication error: " + message;
                evdata.type = SMTP_LIB_SSLTLS_AUTH_METHOD_ERROR;
                ei->onEvent(evdata);
			}
			break;
		case SEND_MAIL_AUTH_C_ERR:
			message = "Invalid credentials supplied";
			if(err_cnt >= rlimits.auth_c)
			{
				setState(false);
				if( verbose_flags & (SMTP_MAIL_HANDLER_DEBUG | SMTP_CRITICAL_EVENTS) )
				{
                    evdata.type = SMTP_LIB_SSLTLS_AUTH_FAILED;
	                evdata.message = "Authentication failed: " + message;
	                ei->onEvent(evdata);
	                evdata.message = "Authentication failed, SMTP client service was stopped";
	                ei->onEvent(evdata);
				}
			}
			else if(verbose_flags & SMTP_MAIL_HANDLER_DEBUG)
			{
                evdata.message = "Attempt: " + to_string(err_cnt) + ", Authentication failed: " + message;
                evdata.type = SMTP_LIB_SSLTLS_AUTH_FAILED;
                ei->onEvent(evdata);
			}
			break;
		case SEND_MAIL_SEND_ERR:
			if(err_duration >= rlimits.send_tw)
			{
				setState(false);
				if( verbose_flags & (SMTP_MAIL_HANDLER_DEBUG | SMTP_CRITICAL_EVENTS) )
				{
                    evdata.type = SMTP_LIB_SEND_TIMEOUT_EXCEEDED;
	                evdata.message = "Send mail error: " + message;
	                ei->onEvent(evdata);
	                evdata.message = "Send timeout exceeded, SMTP client service was stopped";
	                ei->onEvent(evdata);
				}
			}
			else if(verbose_flags & SMTP_MAIL_HANDLER_DEBUG)
			{
                evdata.message = "Attempt: " + to_string(err_cnt) + ", Send mail error: " + message;
                evdata.type = SMTP_LIB_SEND_TIMEOUT_EXCEEDED;
                ei->onEvent(evdata);
			}
			break;
	} // end switch
	return;
}
// Callback function on send events: sent, dropped, waiting(requeued), rejected
void smtpMailer::onSendEvent(const struct postcard &pc, const uint8_t action, string address, int rc, string message)
{
	// No specific action are provided, expecting to be overwritten in child class
}
