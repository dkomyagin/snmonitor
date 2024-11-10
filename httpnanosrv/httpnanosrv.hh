//======================================================================================
// Name        : httpnanosrv.hh
// Author      : Dmitry Komyagin
// Version     : 1.03
// Created on  : Nov 4, 2024
// Copyright   : Public domain
// Description : Header file for HTTP nano server, Linux, ISO C++14
//======================================================================================

#ifndef HTTPNANOSRV_HH_
#define HTTPNANOSRV_HH_

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <unistd.h>

#include <iostream>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <atomic>
#include <functional>
#include <thread>
#include <regex>
#include <condition_variable>

#include "eventinf.hh"

#define HTTP_SERVER_NAME "Embedded KDJ/1.0"

#define MAX_SRV_CONNECTIONS 20
#define MAX_SRV_QUEUE 10

#define HTTP_GET  1
#define HTTP_HEAD 2

#define HTTP_STATUS_OK 					200
#define HTTP_STATUS_NOT_MODIFIED 		304
#define HTTP_STATUS_BAD_REQUEST 		400
#define HTTP_STATUS_NOT_FOUND 			404
#define HTTP_STATUS_REQUEST_TIMEOUT		408
#define HTTP_STATUS_SERVICE_UNAVAILABLE	503

#define STD_CONTENT_TYPE "text/html; charset=utf-8"
#define HTTP_CONNECTION_MAX_IDLE_TIME 180 // in seconds

//
struct httpFields
{
	std::string name;
	std::string token;
};
//
struct httpRequestHeader
{
	uint8_t method; // 1 - GET, 2 - HEAD
	std::string path;
	std::string query;
	std::string fragment;
	std::string version;
	std::vector<struct httpFields> fields;
};

using html_func_t  = std::function< std::string (void *, std::string, std::string, std::string) >;
using html_pages_t = std::map< std::string, std::pair<html_func_t, int> >; // string - page, html_func_t - function, int - max_age
/*
 * Note: HTML page creation function must be like this:
 *       std::string htmlPage(void *srvPtr, std::string path, std::string query, std::string fragment)
 *       To get a pointer to a child class use 'static_cast':
 *       childClass *childClassPtr = static_cast<childClass *>(srvPtr);
 */

//
struct httpReplyOptions
{
	uint8_t rqMethod;
	short statusCode;
	std::string contentType;
	std::string modified_date;
	int cache_max_age;
	std::string connection;
	httpReplyOptions();
};
//
struct httpServerStats
{
	std::atomic<uint32_t> accept_err_cnt = {0};
	std::atomic<uint32_t> reject_err_cnt = {0};
};

// Class 'httpNanoServer' declaration
class httpNanoServer
{
private:
	const std::map<short, std::string> httpStatusCodes =
	{
		{200, "OK"},
		{304, "Not Modified"},
		{400, "Bad Request"},
		{404, "Not Found"},
		{408, "Request Timeout"}
	};
	std::string startTime;
	std::atomic<bool> _runFlag = {true}, _srv_init_flag = {false}, _srv_exit_flag = {false};
	std::mutex ps_mtx;
	in_port_t srvPort;
	int srv_sd = 0;
	std::set<int> peer_sockets;
	bool self_ei;
	eventInformer *ei;
protected:
	struct httpServerStats srvStats;
	html_pages_t htmlPages;
private:
	// Incoming connections listener
	void httpListener();
	// Requests handler
	void httpWorker(int socket);
	// Create HTTP reply
	std::string makeHTTPreply(std::string content, struct httpReplyOptions options);
	// Returns content type based on extension
	std::string contentTypeByExt(std::string path);
	// HTTP reply 304
	std::string httpReply304();
	// HTTP reply 400
	std::string httpReply400();
	// HTTP reply 400
	std::string httpReply404();
	// HTTP reply 408
	std::string httpReply408();
	// HTTP reply 503
	std::string httpReply503();
public:
	// Constructor
	httpNanoServer(in_port_t httpPort, const html_pages_t &sitePages, eventInformer *eventInf = nullptr);
	// Destructor
	~httpNanoServer();
	// Returns boolean value that indicates whether httpNanoServer is stated
	bool isStarted() const;
	// Returns server start time
	std::string getStartTime() const;
	// Returns number of active connections
	size_t getActiveConnections();
};
#endif /* HTTPNANOSRV_HH_ */
