//============================================================================
// Name        : snmnslib.hh
// Author      : Dmitry Komyagin
// Version     : 1.0
// Created on  : Oct 16, 2024
// Copyright   : Public domain
// Description : Heder file for SNMONITOR HTTP nano server, Linux, ISO C++14
//============================================================================

/*************************************************************************************************
 * THIRD-PARTY SOFTWARE NOTE
 *
 * The following software might be used in this product:
 *
 * OpenSSL Library, http://openssl-library.org/
 * Read THIRD-PARTY-LICENSES.txt or visit: http://openssl-library.org/source/license/index.html
 *
 * SQLite Library, http://www.sqlite.org/
 * Read THIRD-PARTY-LICENSES.txt or visit: https://www.sqlite.org/copyright.html
 *************************************************************************************************/

#ifndef SNMNSLIB_HH_
#define SNMNSLIB_HH_

#include "faviconimg.h" // icon arrays
#include "httpnanosrv.hh"
#include "snmgmlib.hh"

// Site pages

// pages
#define HTML_INFO_PATH 				"/info.html"
#define HTML_MAIN_VIEW_SHORT_PATH 	"/main_view_short.html"
#define HTML_MAIN_VIEW_PATH 		"/main_view.html"
#define HTML_MAIN_VIEW_EXT_PATH 	"/main_view_ext.html"
#define HTML_MAIN_VIEW_FULL_PATH 	"/main_view_full.html"
#define HTML_IPV6_VIEW_PATH 		"/ipv6_view.html"
#define HTML_UNKNOWN_HOSTS_PATH 	"/unknown_hosts.html"
#define HTML_DHCP_HOSTS_PATH 		"/dhcp_hosts.html"
#define HTML_NOTIFICATION_PATH 		"/notification.html"
// images
#define IMG_FAVICON_PATH		"/favicon.ico"
#define IMG_APPLE_TOUCH_PATH	"/apple-touch-icon.png"
#define IMG_FAVICON16_PATH 		"/favicon-16x16.png"
#define IMG_FAVICON32_PATH 		"/favicon-32x32.png"
#define IMG_ANDROID512_PATH 	"/android-chrome-512x512.png"
#define IMG_ANDROID192_PATH 	"/android-chrome-192x192.png"
// titles
#define HTML_INFO_TITLE 			"Information"
#define HTML_MAIN_VIEW_SHORT_TITLE 	"Short Hosts view"
#define HTML_MAIN_VIEW_TITLE 		"Hosts view"
#define HTML_MAIN_VIEW_EXT_TITLE 	"Extended Hosts view"
#define HTML_MAIN_VIEW_FULL_TITLE 	"Full Hosts view"
#define HTML_IPV6_VIEW_TITLE 		"IPv6 hosts view"
#define HTML_UNKNOWN_HOSTS_TITLE 	"Unknown hosts view"
#define HTML_DHCP_HOSTS_TITLE 		"DHCP hosts view"
#define HTML_NOTIFICATION_TITLE 	"Notification service information"

// Backgroud color
#define PAGE_BG_COLOR  "#e5e8e8"

// Image path to array translation
const std::map<std::string, std::pair<const char *, size_t>> siteImages =
{
	{ IMG_FAVICON_PATH,     {(const char*) favicon, sizeof(favicon)} },
	{ IMG_APPLE_TOUCH_PATH, {(const char*) apple_touch_icon, sizeof(apple_touch_icon)} },
	{ IMG_FAVICON16_PATH,   {(const char*) favicon16x16, sizeof(favicon16x16)} },
	{ IMG_FAVICON32_PATH,   {(const char*) favicon32x32, sizeof(favicon32x32)} },
	{ IMG_ANDROID512_PATH,  {(const char*) android_chrome_512x512, sizeof(android_chrome_512x512)} },
	{ IMG_ANDROID192_PATH,  {(const char*) android_chrome_192x192, sizeof(android_chrome_192x192)} }
};

// Class 'httpSNMserver' definition
class httpSNMserver : public httpNanoServer
{
public:
	GMonitor *gM;
	snmMailer *smtp;
public:
	httpSNMserver(GMonitor *gMonitor, snmMailer *mailer, in_port_t httpPort, const html_pages_t &sitePages, eventInformer *eventInf);
	std::string htmlInfo();
	void coutInfo();
};
// Site pages
// 'homePage' creation function
std::string homePage(void *srvPtr, std::string, std::string, std::string);
// 'infoPage' creation function
std::string infoPage(void *srvPtr, std::string, std::string query, std::string);
// 'viewPage' creation function
std::string viewPage(void *srvPtr, std::string path, std::string query, std::string);
// 'smtpPage' creation function
std::string smtpPage(void *srvPtr, std::string, std::string, std::string);
// Image loader function
std::string imgLoader(void *, std::string path, std::string, std::string);
// Web manifest function
std::string webManifest(void *, std::string path, std::string, std::string);

#endif /* SNMNSLIB_HH_ */
