//======================================================================================
// Name        : snmeventinf.hh
// Author      : Dmitry Komyagin
// Version     : 0.6
// Created on  : Oct 16, 2024
// Copyright   : Public domain
// Description : Header file for SNMONITOR Informer library, Linux, ISO C++14
//======================================================================================

/*************************************************************************************************
 * THIRD-PARTY SOFTWARE NOTE
 *
 * The following software might be used in this product:
 *
 * OpenSSL Library, http://openssl-library.org/
 * Read THIRD-PARTY-LICENSES.txt or visit: http://openssl-library.org/source/license/index.html
 *************************************************************************************************/

#ifndef SNMEVENTINF_HH_
#define SNMEVENTINF_HH_

#include "snmmailer.hh"
#include "eventinf.hh"

class snmInformer: public eventInformer
{
private:
	snmMailer *smtp;
public:
	snmInformer(snmMailer *mailer);
	void onEvent(const eventData &info) override;
};

#endif /* SNMEVENTINF_HH_ */
