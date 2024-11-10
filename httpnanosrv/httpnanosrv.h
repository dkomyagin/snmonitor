//======================================================================================
// Name        : httpnanosrv.h
// Author      : Dmitry Komyagin
// Version     : 1.0
// Created on  : Oct 3, 2024
// Copyright   : Public domain
// Description : Events definition file for HTTP nano server, Linux, ISO C++14
//======================================================================================

#ifndef HTTPNANOSRV_H_
#define HTTPNANOSRV_H_

#define HTTP_NS_MODULE_NAME     "httpNanoServer"
#define HTTP_NS_STARTED          1
#define HTTP_NS_STOPPED          2
#define HTTP_NS_ERROR_SOCKET    -1
#define HTTP_NS_ERROR_BIND      -2
#define HTTP_NS_ERROR_LISTEN    -3
#define HTTP_NS_ERROR_OPTION    -4
#define HTTP_NS_ERROR_PEER      -5
#define HTTP_NS_ERROR_TIMEOUT   -6

#endif /* HTTPNANOSRV_H_ */
