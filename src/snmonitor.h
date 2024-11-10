//======================================================================================
// Name        : snmonitor.h
// Author      : Dmitry Komyagin
// Version     : 2.25
// Created on  : Nov 8, 2024
// Copyright   : Public domain
// Description : SNMONITOR basic definitions, Linux, ISO C++14
//======================================================================================

#ifndef SNMONITOR_H_
#define SNMONITOR_H_

#define APP_VERSION "2.25 beta"

#define MAIN_DB_FILENAME	"subnet.db"
#define BACKUP_DB_FILENAME	"subnet-snap.db"

#define APP_DEFAULT_HTTP_PORT       8085
#define SMTP_DEFAULT_VERBOSE_LVL    SMTP_CRITICAL_EVENTS | SMTP_MAIL_HANDLER_STOPPED

#endif /* SNMONITOR_H_ */
