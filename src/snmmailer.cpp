//============================================================================
// Name        : snmmailer.cpp
// Author      : Dmitry Komyagin
// Version     : 0.9
// Created on  : Oct 10, 2024
// Copyright   : Public domain
// Description : SNMONITOR SMTP Mailer, Linux, ISO C++14
//============================================================================

/*************************************************************************************************
 * THIRD-PARTY SOFTWARE NOTE
 *
 * The following software might be used in this product:
 *
 * OpenSSL Library, http://openssl-library.org/
 * Read THIRD-PARTY-LICENSES.txt or visit: http://openssl-library.org/source/license/index.html
 *************************************************************************************************/

#include "snmmailer.hh"
#include "snmcommlib.hh"

using namespace std;

// Class 'snmMailer' methods
// Constructor
snmMailer::snmMailer(const struct smtpParams smtpData, uint8_t verbose):smtpMailer(smtpData, verbose)
{
	sndr  = smtpData.sndr;
	rcpts = rcptString2Vector(smtpData.rcpts);
}
//
string snmMailer::infoMssg(char type, string info)
{
	string mssg = getLocalTime() + "  ";
	switch(type)
	{
		case MAIL_TYPE_ALERT:
			mssg += "Alert email";
			break;
		case MAIL_TYPE_TEST:
			mssg += "Notification test email";
			break;
	}
	mssg += info + "\n";
	return mssg;
}
//
void snmMailer::onSendEvent(const struct postcard &pc, const uint8_t action, string address, int rc, string message)
{
	string mssg;
	switch(action)
	{
		case SEND_MAIL_ACT_SENT:
			mssg = infoMssg( pc.type, " was successfully sent" );
			break;
		case SEND_MAIL_ACT_DROP:
			mssg = infoMssg( pc.type, " was dropped: " + message );
			break;
		case SEND_MAIL_ACT_RJCT:
			mssg = infoMssg( pc.type, ": " + message + ", rejected" );
			break;
	}
	if( not mssg.empty() )
	{
		cout << mssg;
	}
}
//
void snmMailer::sendMail(string subj, string mssg, char type)
{
	smtpMailer::sendMail( sndr, rcpts, subj, mssg, type );
}
//
void snmMailer::sendTestMail()
{
	const string subj  = "SNMONITOR email test";
	const string mssg  = "This is a test of the email client";
	sendMail( subj, mssg, MAIL_TYPE_TEST );
}
//
string snmMailer::htmlStats()
{
	stringstream ss;
	vector<string> tblHeader;

	// Table header
	tblHeader = {"Sent e-mails", "Dropped e-mails", "Connection errors", "Input queue", "Output queue"};

	ss << "<tr>" << endl;
	for(string col:tblHeader)
	{
		ss << " <th>" << col << "</th>" << endl;
	}
	ss << "</tr>" << endl;

	// Table body
	ss << "<tr>" << endl;
	ss << " <td>" << stats.sent_cnt << "</td>" << endl;
	ss << " <td>" << stats.drp_mail_cnt << "</td>" << endl;
	ss << " <td>" << stats.conn_err_cnt << "</td>" << endl;
	ss << " <td>" << inQueueSize() << "</td>" << endl;
	ss << " <td>" << outQueueSize() << "</td>" << endl;
	ss << "</tr>" << endl;
	return ss.str();
}
//
string snmMailer::htmlErrStats()
{
	stringstream ss;

	ss << "<tr>" << endl;
	ss << " <th>" << "Setup errors" << "</th>" << endl;
	ss << " <td>" << (int) err_count.setup_err << "</td>" << endl;
	ss << "</tr>\n<tr>" << endl;
	ss << " <th>" << "Socket errors" << "</th>" << endl;
	ss << " <td>" << (int) err_count.socket_err << "</td>" << endl;
	ss << "</tr>\n<tr>" << endl;
	ss << " <th>" << "Open connection errors" << "</th>" << endl;
	ss << " <td>" << (int) err_count.oc_err << "</td>" << endl;
	ss << "</tr>\n<tr>" << endl;
	ss << " <th>" << "TLS/SSL system errors" << "</th>" << endl;
	ss << " <td>" << (int) err_count.tls_sys_err << "</td>" << endl;
	ss << "</tr>\n<tr>" << endl;
	ss << " <th>" << "TLS/SSL connection errors" << "</th>" << endl;
	ss << " <td>" << (int) err_count.tls_con_err << "</td>" << endl;
	ss << "</tr>\n<tr>" << endl;
	ss << " <th>" << "TLS/SSL verification errors" << "</th>" << endl;
	ss << " <td>" << (int) err_count.tls_vrf_err << "</td>" << endl;
	ss << "</tr>\n<tr>" << endl;
	ss << " <th>" << "Authentication method errors" << "</th>" << endl;
	ss << " <td>" << (int) err_count.auth_m_err << "</td>" << endl;
	ss << "</tr>\n<tr>" << endl;
	ss << " <th>" << "Authentication credentials errors" << "</th>" << endl;
	ss << " <td>" << (int) err_count.auth_c_err << "</td>" << endl;
	ss << "</tr>\n<tr>" << endl;
	ss << " <th>" << "Send errors" << "</th>" << endl;
	ss << " <td>" << (int) err_count.send_err << "</td>" << endl;
	ss << "</tr>" << endl;

	return ss.str();
}
//
void snmMailer::coutStats()
{
	stringstream ss;
	ss << "Notification service information:" << endl;
	ss << "SMTP client service: " << (isEnabled() ? "running" : "stopped") << endl;
	ss << "Sent mails: " << stats.sent_cnt << endl;
	ss << "Dropped mails: " << stats.drp_mail_cnt << endl;
	ss << "Connection errors: " << stats.conn_err_cnt << endl;
	ss << "Input  queue size: " << inQueueSize() << endl;
	ss << "Output queue size: " << outQueueSize() << endl;
	ss << "SMTP errors:" << endl;
	ss << "Setup errors: " << (int) err_count.setup_err << endl;
	ss << "Socket errors: " << (int) err_count.socket_err << endl;
	ss << "Open connection errors: " << (int) err_count.oc_err << endl;
	ss << "TLS/SSL system errors: " << (int) err_count.tls_sys_err << endl;
	ss << "TLS/SSL connection errors: " << (int) err_count.tls_con_err << endl;
	ss << "TLS/SSL verification errors: " << (int) err_count.tls_vrf_err << endl;
	ss << "Authentication method errors: " << (int) err_count.auth_m_err << endl;
	ss << "Authentication credentials errors: " << (int) err_count.auth_c_err << endl;
	ss << "Send errors: " << (int) err_count.send_err << endl;

	cout << ss.str();
}


