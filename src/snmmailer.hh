//======================================================================================
// Name        : snmmailer.hh
// Author      : Dmitry Komyagin
// Version     : 0.9
// Created on  : Oct 10, 2024
// Copyright   : Public domain
// Description : Header file for SNMONITOR SMTP Mailer, Linux, ISO C++14
//======================================================================================

/*************************************************************************************************
 * THIRD-PARTY SOFTWARE NOTE
 *
 * The following software might be used in this product:
 *
 * OpenSSL Library, http://openssl-library.org/
 * Read THIRD-PARTY-LICENSES.txt or visit: http://openssl-library.org/source/license/index.html
 *************************************************************************************************/

#ifndef SNMMAILER_HH_
#define SNMMAILER_HH_

#include "smtp.hh"

#define MAIL_TYPE_ALERT 'a' // Alert mail
#define MAIL_TYPE_TEST  't' // Test mail

// Class 'snmMailer' definition
class snmMailer: public smtpMailer
{
private:
	std::string sndr;
	std::vector<std::string> rcpts;
public:
	// Constructor
	snmMailer(const struct smtpParams smtpData, uint8_t verbose = SMTP_NO_DEBUG);
	//
	void onSendEvent(const struct postcard &pc, const uint8_t action, std::string address, int rc, std::string message) override;
	//
	std::string infoMssg(char type, std::string info);
	//
	void sendMail(std::string subj, std::string mssg, char type);
	//
	void sendTestMail();
	//
	std::string htmlStats();
	//
	std::string htmlErrStats();
	// Outputs statistics to console
	void coutStats();
};

#endif /* SNMMAILER_HH_ */
