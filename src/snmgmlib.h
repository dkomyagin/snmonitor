//======================================================================================
// Name        : snmgmlib.h
// Author      : Dmitry Komyagin
// Version     : 0.92
// Created on  : Oct 31, 2024
// Copyright   : Public domain
// Description : Header file for SNMONITOR General Monitor library
//======================================================================================

#ifndef SNMGMLIB_H_
#define SNMGMLIB_H_

#define SNM_AAH_MODULE_NAME "arpAnycastHelper"
// Informer message type
#define SNM_AAH_STOPPED 		 1
#define SNM_AAH_ERROR_SOCKET	-1
#define SNM_AAH_ERROR_BIND 		-2
#define SNM_AAH_ERROR_OPTION	-3
#define SNM_AAH_ERROR_SEND		-4

#define SNM_GM_MODULE_NAME "snmGMonitor"
// Informer message type
#define SNM_GM_SRVC_STOPPED		  1
#define SNM_GM_NL_STOPPED		  2
#define SNM_GM_STOPPED			  3
#define SNM_GM_IF_UP			  4
#define SNM_GM_IF_DOWN			  5
#define SNM_GM_ALL_DOWN			  6
#define SNM_GM_TO_DOWN			  7
#define SNM_GM_ACTIVE_IFS         8
#define SNM_GM_STARTED            9
#define SNM_GM_ERROR_SOCKET		 -1
#define SNM_GM_ERROR_BIND 		 -2
#define SNM_GM_ERROR_OPTION		 -3
#define SNM_GM_NLMSG_ERROR		 -4
#define SNM_GM_INIT_ERROR		 -5
#define SNM_GM_ERROR_IOCTL		 -6
#define SNM_GM_ERROR_GETIFADDRS	 -7
#define SNM_GM_ERROR_SEND 		 -8
#define SNM_GM_ERROR_TO_OPTION	 -9
#define SNM_GM_ERROR_BIND_BCA	-10
#define SNM_GM_ERROR_BIND_MCG	-11
#define SNM_GM_ERROR_ADD_MBSH	-12
#define SNM_GM_ERROR_CLEAR_MBSH	-13
#define SNM_GM_ERROR_GET_SINFO	-14
#define SNM_GM_ERROR_HTTP_ADDR	-15
#define SNM_GM_ERROR_SQL		-16

#endif /* SNMGMLIB_H_ */
