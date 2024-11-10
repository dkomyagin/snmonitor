//======================================================================================
// Name        : smtp.hh
// Author      : Dmitry Komyagin
// Version     : 1.0
// Created on  : Oct 29, 2024
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

#ifndef SMTP_HH_
#define SMTP_HH_

#include "smtplib.hh"

// Verbosity flags
#define SMTP_NO_DEBUG 				0
#define SMTP_COMMAND_DEBUG		    0b00000001
#define SMTP_CONNECTION_DEBUG	    0b00000010
#define SMTP_SSL_CONNECTION_DEBUG   0b00000100
#define SMTP_MAIL_HANDLER_DEBUG		0b00001000
#define SMTP_SEND_MAIL_DEBUG		0b00010000
#define SMTP_CRITICAL_EVENTS		0b00100000
#define SMTP_MAIL_HANDLER_STOPPED   0b01000000
#define SMTP_DEBUG_ALL 				0xFF

// Class 'smtpMailer' definition
class smtpMailer: protected protoMailer
{
protected:
	// Mail sender, returns 0 on successes, error code or number of deferred mails
	int Sender();
	// Mail handler
	void mailHandler();
	// Creates email message in standard format (RFC 5322)
	virtual std::string emailForm(std::string from_addr, std::string to_addr, std::string subj, std::string txt);
public:
	// Constructor
	smtpMailer(const struct smtpParams smtpData, uint8_t verbose = SMTP_NO_DEBUG, eventInformer *eventInf = nullptr);
	// Destructor
	virtual ~smtpMailer();
	// Returns true if smtpMailer is started
	bool isStarted() const;
	// Returns true if mail processing is on
	bool isEnabled() const;
	// Enables or disables mail processing
	void setState(bool state);
	// Returns input queue length (thread safe)
	size_t inQueueSize();
	// Returns output queue length (thread safe)
	size_t outQueueSize();
	// Tests connection to SMTP server, return 0 on success or error code
	int testConnection();
	// Sends mail, returns 0 on success, -1 if sender string empty, -2 if recipients string empty
	int sendMail(std::string sender, std::string recipients, std::string subj, std::string mssg, char type);
	// Sends mail, returns 0 on success, -1 if sender string empty, -2 if recipients vector empty
	int sendMail(std::string sender, std::vector<std::string> recipients, std::string subj, std::string mssg, char type);
	// Callback function on send events: sent, dropped, waiting(requeued), rejected
	virtual void onSendEvent(const struct postcard &pc, const uint8_t action, std::string address, int rc, std::string message);
	// Callback function on send errors
	virtual void onSendError(int rc, uint32_t err_cnt, seconds err_duration, std::string message);
};

#endif /* SMTP_HH_ */
