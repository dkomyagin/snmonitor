//============================================================================
// Name        : snmeventinfo.cpp
// Author      : Dmitry Komyagin
// Version     : 0.6
// Created on  : Oct 16, 2024
// Copyright   : Public domain
// Description : SNMONITOR Informer library, Linux, ISO C++14
//============================================================================

/*************************************************************************************************
 * THIRD-PARTY SOFTWARE NOTE
 *
 * The following software might be used in this product:
 *
 * OpenSSL Library, http://openssl-library.org/
 * Read THIRD-PARTY-LICENSES.txt or visit: http://openssl-library.org/source/license/index.html
 *************************************************************************************************/

#include "snmeventinf.hh"
#include "snmdblib.h"
#include "snmcommlib.hh"
#include "httpnanosrv.h"
#include "snmgmlib.h"
#include "snmrtlib.h"

using namespace std;

// Class 'snmInformer' methods
// Constructor
snmInformer::snmInformer(snmMailer *mailer)
{
	smtp = mailer;
}
// Outputs event information to console
void snmInformer::onEvent(const eventData &info)
{
	string infoMssg = "";

	//
	if(info.module == SNM_DB_MODULE_NAME)
	{
		if(info.type < 0)
		{
			infoMssg = getLocalTime() + "  " + info.module + "::" + info.routine + ": " + info.message + "\n";
		}
		else
		{
			infoMssg = getLocalTime() + "  " + info.message  + "\n";
		}
		switch(info.type)
		{
		case SNM_DB_NEW_MAC_ENTRY:
			cout << infoMssg;
			if(smtp) smtp->sendMail( "SNMONITOR alert message", infoMssg, MAIL_TYPE_ALERT );
			break;
		case SNM_DB_NEW_IPV6_ENTRY:
			cout << infoMssg;
			if(smtp) smtp->sendMail( "SNMONITOR alert message", infoMssg, MAIL_TYPE_ALERT );
			break;
		default:
			cerr << infoMssg;
		}
		return;
	}
	//
	if(info.module == SNM_GM_MODULE_NAME)
	{
		if( (info.type == SNM_GM_IF_UP) or (info.type == SNM_GM_IF_DOWN) )
		{
			cout << getLocalTime() + "  " + info.message + "\n";
			return;
		}
		else if(info.type == SNM_GM_SRVC_STOPPED)
		{
		    if(verbose == 1) cout << info.message +"\n";
		    return;
		}
	}
	//
    if( (info.module == SNM_AAH_MODULE_NAME) and (info.type == SNM_AAH_STOPPED) )
    {
        if(verbose == 1) cout << info.message +"\n";
        return;
    }
	//
	if(info.module == SNM_RTC_MODULE_NAME)
	{
		if(info.type == SNM_RTC_CRITICAL_ERROR)
		{
			cerr << getLocalTime() + "  " + info.message + "\n";
			return;
		}
		if(info.type == SNM_RTC_SQL_ERR_ALARM)
		{
			infoMssg = getLocalTime() + "  " + info.message + "\n";
			cerr << infoMssg;
			if(smtp) smtp->sendMail( "SNMONITOR alert message", infoMssg, MAIL_TYPE_ALERT );
			return;
		}
	}
	//
	if(info.message == "")
	{
		cout << info.module + "::" + info.routine + ": no message provided\n";
	}
	else if(info.type < 0)
	{
		cerr << getLocalTime() + "  " + info.module + "::" + info.routine + ": " + info.message + "\n";
	}
	else
	{
		cout << info.message +"\n";
	}
}



