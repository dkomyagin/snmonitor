//============================================================================
// Name        : snmnslib.cpp
// Author      : Dmitry Komyagin
// Version     : 1.01
// Created on  : Oct 28, 2024
// Copyright   : Public domain
// Description : SNMONITOR HTTP nano server, Linux, ISO C++14
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

#include "snmonitor.h"
#include "snmnslib.hh"

using namespace std;

// Class 'httpSNMserver' methods
// Constructor
httpSNMserver::httpSNMserver(GMonitor *gMonitor, snmMailer *mailer, in_port_t httpPort,
							 const html_pages_t &sitePages, eventInformer *eventInf)
							:httpNanoServer(httpPort, sitePages, eventInf)
{
	gM = gMonitor;
	smtp = mailer;
}
//
string httpSNMserver::htmlInfo()
{
	stringstream ss;
	vector<string> tblHeader;

	// Table header
	tblHeader = {"Active connections", "Accept errors", "Rejected connections"};

	ss << "<tr>" << endl;
	for(string col:tblHeader)
	{
		ss << " <th>" << col << "</th>" << endl;
	}
	ss << "</tr>" << endl;

	// Table body
	ss << "<tr>" << endl;
	ss << " <td>" << getActiveConnections() << "</td>" << endl;
	ss << " <td>" << srvStats.accept_err_cnt << "</td>" << endl;
	ss << " <td>" << srvStats.reject_err_cnt << "</td>" << endl;
	ss << "</tr>" << endl;
	return ss.str();
}
//
void httpSNMserver::coutInfo()
{
	stringstream ss;

	ss << "HTTP server <" << HTTP_SERVER_NAME << "> started at " << getStartTime() << endl;
	ss << "Active connections: " << getActiveConnections() << endl;
	ss << "Accept errors: " << srvStats.accept_err_cnt << endl;
	ss << "Rejected connections: " << srvStats.reject_err_cnt << endl;
	cout << ss.str();
}

// Site pages
//
static string htmlViewTable(sqlite3 *db, char suf, uint8_t days, uint16_t *rows)
{
	sqlite3_stmt* stmt;
	int rc;
	char *txt;
	stringstream ss;
	string tbl, query;
	vector<string> tblHeader;

	switch(suf)
	{
	case 's':
		tbl = "MAIN_VIEW_SHORT";
		tblHeader = {"Update time (UTC)", "MAC address", "IPv4 address", "DNS name", "NBNS name", "mDNS name", "DHCP name"};
		break;
	case 'e':
		tbl = "MAIN_VIEW_EXT";
		tblHeader = {"Update time (UTC)", "MAC address", "IPv4 address", "DNS name", "NBNS name", "mDNS name", "UPnP info", "DHCP name", "Vendor"};
		break;
	case 'f':
		tbl = "MAIN_VIEW_FULL";
		tblHeader = {"Update time (UTC)", "MAC address", "IPv4 address", "DNS name", "NBNS name", "mDNS name", "UPnP info", "LLDP name", "DHCP name", "LLMNR name", "Vendor"};
		break;
	case 'm':
		tbl = "MAIN_VIEW";
		tblHeader = {"Update time (UTC)", "MAC address", "IPv4 address", "DNS name", "NBNS name", "mDNS name", "DHCP name", "Vendor"};
		break;
	case 'v':
		tbl = "IPV6_VIEW";
		tblHeader = {"Update time (UTC)", "MAC address", "IPv6 address", "If", "IPv4 address", "DNS name", "mDNS name", "LLMNR name", "Vendor"};
		break;
	case 'u':
		tbl = "UNKNOWN_HOSTS_VIEW";
		tblHeader = {"Update time (UTC)", "MAC address", "IPv4 address", "Vendor"};
		break;
	case 'd':
		tbl = "DHCP_VIEW";
		tblHeader = {"MAC address", "Update time (UTC)", "Entry time (UTC)", "Host name", "Vendor identifier", "DHCP requested parameters", "DHCP options"};
		break;
	}

	// Table header
	ss << "<tr>" << endl;
	for(string l:tblHeader)
	{
		ss << " <th>" << l << "</th>" << endl;
	}
	ss << "</tr>" << endl;
	// Table body
	query = "SELECT * FROM " + tbl;
	if(days) query += " WHERE updated > datetime('now','-" + to_string(days) + " day')";

	sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, NULL);

	*rows = 0;
	while( ( rc = sqlite3_step(stmt) ) == SQLITE_ROW )
	{
		++(*rows);
		ss << "<tr>" << endl;
		for(uint8_t i = 0; i < tblHeader.size(); ++i)
		{
			txt = (char *) sqlite3_column_text(stmt, i);
			ss << " <td>" << (txt == nullptr ? "" : txt) << "</td>" << endl;
		}
		ss << "</tr>" << endl;
	}
	//release resources
	sqlite3_finalize(stmt);

	return ss.str();
}
//
static string getMessageLog(sqlite3 *db, uint8_t days)
{
	sqlite3_stmt* stmt;
	int rc;
	stringstream ss;
	vector<string> tblHeader = {"Time (UTC)", "Message"};
	string tbl, query;

	// Table header
	ss << "<tr>" << endl;
	for(string col:tblHeader)
	{
		ss << " <th>" << col << "</th>" << endl;
	}
	ss << "</tr>" << endl;

	// Table body
	query = "SELECT * FROM MESSAGE_LOG ";
	if(days) query += " WHERE timestamp > datetime('now','-" + to_string(days) + " day')";
	query += " ORDER BY timestamp DESC;";

	sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, NULL);

	while( ( rc = sqlite3_step(stmt) ) == SQLITE_ROW )
	{
		ss << "<tr>" << endl;
		for(uint8_t i = 0; i < tblHeader.size(); ++i)
		{
			ss << " <td>" << ( (char *) sqlite3_column_text(stmt, i) ) << "</td>" << endl;
		}
		ss << "</tr>" << endl;
	}
	//release resources
	sqlite3_finalize(stmt);

	return ss.str();
}
// 'homePage' creation function
string homePage(void *srvPtr, string, string, string)
{
	httpSNMserver *nS = static_cast<httpSNMserver *>(srvPtr);
	stringstream content;
	content << "<!DOCTYPE html>" << endl;
	content << "<html lang=\"en-US\">" << endl;
	content << "<head>" << endl;
	content << "<meta charset=\"UTF-8\">" << endl;
	content << "<meta name=\"viewport\" content=\"width=device-width, initial-scale=0.8\">" << endl;
	content << "<title>snmonitor-Home</title>" << endl;
	content << "<link rel=\"apple-touch-icon\" sizes=\"180x180\" href=\"" << IMG_APPLE_TOUCH_PATH << "\">" << endl;
	content << "<link rel=\"icon\" type=\"image/png\" sizes=\"32x32\" href=\"" << IMG_FAVICON32_PATH << "\">" << endl;
	content << "<link rel=\"icon\" type=\"image/png\" sizes=\"16x16\" href=\"" << IMG_FAVICON16_PATH << "\">" << endl;
	content << "<link rel=\"manifest\" href=\"/site.webmanifest\">" << endl;
	content << "<script>" << endl;
	content << "function go(url){" << endl;
	content << "  document.location.href = url + \"?days=\" +document.querySelector(\"[name='days']:checked\").value;" << endl;
	content << "}" << endl;
	content << "</script>" << endl;
	content << "<style>" << endl;
	content << "  body {background-color: " << PAGE_BG_COLOR << ";}" << endl;
	content << "  a:link {color:blue;}" << endl;
	content << "  a:visited {color:blue;}" << endl;
	content << "  a:hover {color:#0066ff;}" << endl;
	content << "  a:active {color:blue;}" << endl;
	content << "  a {text-decoration: none;}" << endl;
	content << "  fieldset {" << endl;
	content << "    display: inline;" << endl;
	content << "    text-align: left;" << endl;
	content << "    border-color: #fdfefe;" << endl;
	content << "    border-style: solid;" << endl;
	content << "    border-radius: 5px;" << endl;
	content << "  }" << endl;
	content << "  footer {" << endl;
	content << "    text-align:center;" << endl;
	content << "    font-size: 11px;" << endl;
	content << "    font-family: \"Times New Roman\", Times, serif;" << endl;
	content << "    font-style: italic;" << endl;
	content << "  }" << endl;
	content << "  .box {" << endl;
	content << "    border-radius: 25px;" << endl;
	content << "    background: #bfc9ca;" << endl;
	content << "    padding: 10px;" << endl;
	content << "    margin: 20px 0px 0px 10px;" << endl;
	content << "    width: 400px;" << endl;
	content << "    height: 405px;" << endl;
	content << "    font-family: Arial, sans-serif;" << endl;
	content << "    font-size: 16px;" << endl;
	content << "  }" << endl;
	content << "  .menu {" << endl;
	content << "    margin: 20px 20px 20px 20px;" << endl;
	content << "    padding: 0;" << endl;
	content << "    list-style-position: inside;" << endl;
	content << "    font-size: 22px;" << endl;
	content << "    font-weight: bold;" << endl;
	content << "    list-style-type: disc;" << endl;
	content << "    height: 195px;" << endl;
	content << "  }" << endl;
	content << "  .radio-box {" << endl;
	content << "    margin: 35px 5px 15px 5px;" << endl;
	content << "    text-align: center;" << endl;
	content << "    height: 66px;" << endl;
	content << "  }" << endl;
	content << "  .radio-inline {" << endl;
	content << "    accent-color: blue;" << endl;
	content << "  }" << endl;
	content << "  .line {" << endl;
	content << "    height: 1px;" << endl;
	content << "    background: black;" << endl;
	content << "  }" << endl;
	content << "</style>" << endl;
	content << "</head>" << endl;
	content << "<body>" << endl;
	content << "<div class=\"box\">" << endl;
	content << "<h2 style=\"text-align:center\">SNMONITOR</h2>" << endl;
	content << "<ul class=\"menu\">" << endl;
	content << "  <li><a href=\"javascript:go('" << HTML_INFO_PATH << "');\">" << HTML_INFO_TITLE << "</a></li>" << endl;
	content << "  <li><a href=\"javascript:go('" << HTML_MAIN_VIEW_SHORT_PATH << "');\">" << HTML_MAIN_VIEW_SHORT_TITLE << "</a></li>" << endl;
	content << "  <li><a href=\"javascript:go('" << HTML_MAIN_VIEW_PATH << "');\">" << HTML_MAIN_VIEW_TITLE << "</a></li>" << endl;
	content << "  <li><a href=\"javascript:go('" << HTML_MAIN_VIEW_EXT_PATH << "');\">" << HTML_MAIN_VIEW_EXT_TITLE << "</a></li>" << endl;
	content << "  <li><a href=\"javascript:go('" << HTML_MAIN_VIEW_FULL_PATH << "');\">" << HTML_MAIN_VIEW_FULL_TITLE << "</a></li>" << endl;
	content << "  <li><a href=\"javascript:go('" << HTML_UNKNOWN_HOSTS_PATH << "');\">" << HTML_UNKNOWN_HOSTS_TITLE << "</a></li>" << endl;
	content << "  <li><a href=\"javascript:go('" << HTML_DHCP_HOSTS_PATH << "');\">" << HTML_DHCP_HOSTS_TITLE << "</a></li>" << endl;
	if( nS->gM->isIPv6enabled() )
	{
		content << "  <li><a href=\"javascript:go('" << HTML_IPV6_VIEW_PATH << "');\">" << HTML_IPV6_VIEW_TITLE << "</a></li>" << endl;
	}
	content << "</ul>" << endl;
	content << "<div class=\"radio-box\">" << endl;
	content << "  <form>" << endl;
	content << "    <fieldset>" << endl;
	content << "	  <legend>Days to show</legend>" << endl;
	content << "      <label class=\"radio-inline\">" << endl;
	content << "        <input type=\"radio\" name=\"days\" value=\"0\" checked>all" << endl;
	content << "      </label>" << endl;
	for( int i=1; i < 10; ++i)
	{
		content << "      <label class=\"radio-inline\">" << endl;
		content << "        <input type=\"radio\" name=\"days\" value=\"" << i << "\">" << i << endl;
		content << "      </label>" << endl;
	}
	content << "    </fieldset>" << endl;
	content << "  </form>" << endl;
	content << "</div>" << endl;
	content << "<footer>" << endl;
	content << "<div class=\"line\"></div>" << endl;
	content << "<p>SNMONITOR &laquo;" << APP_VERSION << "&raquo; Dmitry Komyagin 2023</p>" << endl;
	content << "</footer>" << endl;
	content << "</div>" << endl;

	content << "</body>" << endl;
	content << "</html>" << endl;
	return content.str();
}
// 'infoPage' creation function
string infoPage(void *srvPtr, string, string query, string)
{
	httpSNMserver *nS = static_cast<httpSNMserver *>(srvPtr);
	stringstream content;
	uint8_t numIf, numStat;
	const string startTime = nS->gM->getStartTime();
	const string ifTable = nS->gM->htmlInfo(&numIf);
	const string statTable = nS->gM->htmlStatistics(&numStat);
	const string title = HTML_INFO_TITLE;
	uint8_t days = 0;
	if(query.rfind("days=", 0) == 0) days = ch2int( query[5] );
	if(days == 0) days = 14; // maximum 14 last days
	const string mssgTable = getMessageLog(nS->gM->mdb, days);

	content << "<!DOCTYPE html>" << endl;
	content << "<html lang=\"en-US\">" << endl;
	content << "<head>" << endl;
	content << "<meta charset=\"UTF-8\">" << endl;
	content << "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">" << endl;
	content << "<title>snmonitor-" << title << "</title>" << endl;
	content << "<link rel=\"apple-touch-icon\" sizes=\"180x180\" href=\"" << IMG_APPLE_TOUCH_PATH << "\">" << endl;
	content << "<link rel=\"icon\" type=\"image/png\" sizes=\"32x32\" href=\"" << IMG_FAVICON32_PATH << "\">" << endl;
	content << "<link rel=\"icon\" type=\"image/png\" sizes=\"16x16\" href=\"" << IMG_FAVICON16_PATH << "\">" << endl;
	content << "<link rel=\"manifest\" href=\"/site.webmanifest\">" << endl;
	content << "<script>" << endl;
	content << "function go(url){" << endl;
	content << "  document.location.href = url;" << endl;
	content << "}" << endl;
	content << "</script>" << endl;
	content << "<style>" << endl;
	content << "body {background-color: " << PAGE_BG_COLOR << ";font-family: Arial, sans-serif;}" << endl;
	content << "table, th, td {" << endl;
	content << "  border:1px solid black;" << endl;
	content << "  border-collapse: collapse;" << endl;
	content << "  font-family: \"Courier New\", Courier, monospace;" << endl;
	content << "  white-space: nowrap;" << endl;
	content << "  font-size: 12px;" << endl;
	content << "  height: 18px;" << endl;
	content << "  vertical-align: middle;" << endl;
	content << "}" << endl;
	content << "td {font-weight: 500;}" << endl;
	content << "h3 {font-size: 16px; font-weight: bold; margin-bottom: 0.2em;}" << endl;
	content << "p {margin: 0; font-size: 15px;}" << endl;
	content << "a:hover {" << endl;
	content << "  background-color: #ddd;" << endl;
	content << "  color: black;" << endl;
	content << "}" << endl;
	content << ".button {" << endl;
	content << "  background-color:" << PAGE_BG_COLOR << ";" << endl;
	content << "  border: none;" << endl;
	content << "  border-radius: 50%;" << endl;
	content << "  color: black;" << endl;
	content << "  margin: 0;" << endl;
	content << "  padding: 0;" << endl;
	content << "  line-height: 33px;" << endl;
	content << "  height: 34px;" << endl;
	content << "  width: 34px;" << endl;
	content << "  text-align: center;" << endl;
	content << "  vertical-align: middle;" << endl;
	content << "  text-decoration: none;" << endl;
	content << "  display: inline-block;" << endl;
	content << "  font-family: Arial, sans-serif;" << endl;
	content << "  cursor: pointer;" << endl;
	content << "}" << endl;
	content << ".button-home {transform: rotate(180deg); font-size: 26px;}" << endl;
	content << ".button-reload {margin-left: 30px; transform: rotate(90deg); font-size: 32px; font-weight: bold;}" << endl;
	content << ".table-name {" << endl;
	content << "  margin-left: 5px;" << endl;
	content << "  font-size: 26px;" << endl;
	content << "  display: inline-block;" << endl;
	content << "  vertical-align: middle;" << endl;
	content << "  font-weight: bold;" << endl;
	content << "}" << endl;
	content << "</style>" << endl;
	content << "</head>" << endl;
	content << "<body>" << endl;
	content << "<a href=\"/\" class=\"button button-home\" title=\"Home\">&#10140;</a>" << endl;
	content << "<label class=\"table-name\">" << title << "</label>" << endl;
	content << "<a onClick=\"window.location.reload();\" class=\"button button-reload\" title=\"Reload\">&#8635;</a>" << endl;
	content << "<h3>" << "SNMONITOR started: " << startTime << " UTC</h3>" << endl;
	content << "<h3>" << "Number of active interfaces: " << (int) numIf << "</h3>" << endl;
	content << "<table style=\"width:40%\">" << endl;
	content << ifTable;
	content << "</table>" << endl;
	content << "<h3>" << "Total services registered: " << (int) numStat << "</h3>" << endl;
	content << "<table style=\"width:50%\">" << endl;
	content << statTable;
	content << "</table>" << endl;
	content << "<h3>" << "HTTP server &laquo;" << HTTP_SERVER_NAME << "&raquo;" << "</h3>" << endl;
	content << "<table style=\"width:25%\">" << endl;
	content << nS->htmlInfo();
	content << "</table>" << endl;
	if(nS->smtp != nullptr)
	{
		content << "  <h3><a href=\"javascript:go('" << HTML_NOTIFICATION_PATH << "');\">" << HTML_NOTIFICATION_TITLE << "</a></h3>" << endl;
	}
	content << "<h3>" << "Message log for the last " << (int) days << ( (days == 1) ? " day" : " days" ) << " :" << "</h3>" << endl;
	content << "<table style=\"width:40%\">" << endl;
	content << mssgTable;
	content << "</table>" << endl;
	content << "</body>" << endl;
	content << "</html>" << endl;
	return content.str();
}
// 'viewPage' creation function
string viewPage(void *srvPtr, string path, string query, string)
{
	httpSNMserver *nS = static_cast<httpSNMserver *>(srvPtr);
	stringstream content;
	char suf = 'm';   // just in case
	uint8_t days = 0; // just in case
	uint16_t rows;
	string title, table;

	if(path == HTML_MAIN_VIEW_SHORT_PATH)
	{
		suf = 's';
		title = HTML_MAIN_VIEW_SHORT_TITLE;
	}
	if(path == HTML_MAIN_VIEW_PATH)
	{
		suf = 'm';
		title = HTML_MAIN_VIEW_TITLE;
	}
	if(path == HTML_MAIN_VIEW_EXT_PATH)
	{
		suf = 'e';
		title = HTML_MAIN_VIEW_EXT_TITLE;
	}
	if(path == HTML_MAIN_VIEW_FULL_PATH)
	{
		suf = 'f';
		title = HTML_MAIN_VIEW_FULL_TITLE;
	}
	if(path == HTML_IPV6_VIEW_PATH)
	{
		suf = 'v';
		title = HTML_IPV6_VIEW_TITLE;
	}
	if(path == HTML_UNKNOWN_HOSTS_PATH)
	{
		suf = 'u';
		title = HTML_UNKNOWN_HOSTS_TITLE;
	}
	if(path == HTML_DHCP_HOSTS_PATH)
	{
		suf = 'd';
		title = HTML_DHCP_HOSTS_TITLE;
	}

	if(query.rfind("days=", 0) == 0) days = ch2int( query[5] );
	table = htmlViewTable(nS->gM->mdb, suf, days, &rows);

	content << "<!DOCTYPE html>" << endl;
	content << "<html lang=\"en-US\">" << endl;
	content << "<head>" << endl;
	content << "<meta charset=\"UTF-8\">" << endl;
	content << "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">" << endl;
	content << "<title>snmonitor-" << title << "</title>" << endl;
	content << "<link rel=\"apple-touch-icon\" sizes=\"180x180\" href=\"" << IMG_APPLE_TOUCH_PATH << "\">" << endl;
	content << "<link rel=\"icon\" type=\"image/png\" sizes=\"32x32\" href=\"" << IMG_FAVICON32_PATH << "\">" << endl;
	content << "<link rel=\"icon\" type=\"image/png\" sizes=\"16x16\" href=\"" << IMG_FAVICON16_PATH << "\">" << endl;
	content << "<link rel=\"manifest\" href=\"/site.webmanifest\">" << endl;
	content << "<style>" << endl;
	content << "body {background-color: " << PAGE_BG_COLOR << ";font-family: Arial, sans-serif;}" << endl;
	content << "table, th, td {" << endl;
	content << "  border:1px solid black;" << endl;
	content << "  border-collapse: collapse;" << endl;
	content << "  font-family: \"Courier New\", Courier, monospace;" << endl;
	content << "  white-space: nowrap;" << endl;
	content << "  font-size: 12px;" << endl;
	content << "  height: 18px;" << endl;
	content << "  vertical-align: middle;" << endl;
	content << "}" << endl;
	content << "tr:nth-child(even) {" << endl;
	content << "  background-color: #e5e8e8;" << endl;
	content << "  font-weight: 500;" << endl;
	content << "}" << endl;
	content << "tr:nth-child(odd) {" << endl;
	content << "  background-color: #ccd1d1;" << endl;
	content << "  font-weight: 500;" << endl;
	content << "}" << endl;
	content << "a:hover {" << endl;
	content << "  background-color: #ddd;" << endl;
	content << "  color: black;" << endl;
	content << "}" << endl;
	content << ".button {" << endl;
	content << "  background-color:" << PAGE_BG_COLOR << ";" << endl;
	content << "  border: none;" << endl;
	content << "  border-radius: 50%;" << endl;
	content << "  color: black;" << endl;
	content << "  margin: 0;" << endl;
	content << "  padding: 0;" << endl;
	content << "  line-height: 33px;" << endl;
	content << "  height: 34px;" << endl;
	content << "  width: 34px;" << endl;
	content << "  text-align: center;" << endl;
	content << "  vertical-align: middle;" << endl;
	content << "  text-decoration: none;" << endl;
	content << "  display: inline-block;" << endl;
	content << "  font-family: Arial, sans-serif;" << endl;
	content << "  cursor: pointer;" << endl;
	content << "}" << endl;
	content << ".button-home {transform: rotate(180deg); font-size: 26px;}" << endl;
	content << ".button-reload {margin-left: 30px; transform: rotate(90deg); font-size: 32px; font-weight: bold;}" << endl;
	content << ".table-name {" << endl;
	content << "  margin-left: 5px;" << endl;
	content << "  font-size: 26px;" << endl;
	content << "  display: inline-block;" << endl;
	content << "  vertical-align: middle;" << endl;
	content << "  font-weight: bold;" << endl;
	content << "}" << endl;
	content << "</style>" << endl;
	content << "</head>" << endl;
	content << "<body>" << endl;
	content << "<a href=\"/\" class=\"button button-home\" title=\"Home\">&#10140;</a>" << endl;
	content << "<label class=\"table-name\">" << title << "</label>" << endl;
	content << "<a onClick=\"window.location.reload();\" class=\"button button-reload\" title=\"Reload\">&#8635;</a>" << endl;
	content << "<p style=\"font-size: 14px; font-weight: bold;\">Total records: " << rows;
	if(days) content << " updated for the last " << (int) days << ( (days == 1) ? " day" : " days" );
	content	<< "</p>" << endl;
	content << "<table style=\"width:100%\">" << endl;
	content << table;
	content << "</table>" << endl;
	content << "</body>" << endl;
	content << "</html>" << endl;
	return content.str();
}
// 'smtpPage' creation function
string smtpPage(void *srvPtr, string, string, string)
{
	httpSNMserver *nS = static_cast<httpSNMserver *>(srvPtr);
	stringstream content;
	string state = nS->smtp->isEnabled() ? "running" : "stopped";
	string statTable = nS->smtp->htmlStats();
	string errTable = nS->smtp->htmlErrStats();
	string title = HTML_NOTIFICATION_TITLE;

	content << "<!DOCTYPE html>" << endl;
	content << "<html lang=\"en-US\">" << endl;
	content << "<head>" << endl;
	content << "<meta charset=\"UTF-8\">" << endl;
	content << "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">" << endl;
	content << "<title>snmonitor-" << title << "</title>" << endl;
	content << "<link rel=\"apple-touch-icon\" sizes=\"180x180\" href=\"" << IMG_APPLE_TOUCH_PATH << "\">" << endl;
	content << "<link rel=\"icon\" type=\"image/png\" sizes=\"32x32\" href=\"" << IMG_FAVICON32_PATH << "\">" << endl;
	content << "<link rel=\"icon\" type=\"image/png\" sizes=\"16x16\" href=\"" << IMG_FAVICON16_PATH << "\">" << endl;
	content << "<link rel=\"manifest\" href=\"/site.webmanifest\">" << endl;
	content << "<style>" << endl;
	content << "body {background-color: " << PAGE_BG_COLOR << ";font-family: Arial, sans-serif;}" << endl;
	content << "table, th, td {" << endl;
	content << "  border:1px solid black;" << endl;
	content << "  border-collapse: collapse;" << endl;
	content << "  font-family: \"Courier New\", Courier, monospace;" << endl;
	content << "  white-space: nowrap;" << endl;
	content << "  font-size: 12px;" << endl;
	content << "  height: 18px;" << endl;
	content << "  vertical-align: middle;" << endl;
	content << "}" << endl;
	content << "td {font-weight: 500;}" << endl;
	content << "h3 {font-size: 16px; font-weight: bold; margin-bottom: 0.2em;}" << endl;
	content << "p {margin: 0; font-size: 15px;}" << endl;
	content << "a:hover {" << endl;
	content << "  background-color: #ddd;" << endl;
	content << "  color: black;" << endl;
	content << "}" << endl;
	content << ".button {" << endl;
	content << "  background-color:" << PAGE_BG_COLOR << ";" << endl;
	content << "  border: none;" << endl;
	content << "  border-radius: 50%;" << endl;
	content << "  color: black;" << endl;
	content << "  margin: 0;" << endl;
	content << "  padding: 0;" << endl;
	content << "  line-height: 33px;" << endl;
	content << "  height: 34px;" << endl;
	content << "  width: 34px;" << endl;
	content << "  text-align: center;" << endl;
	content << "  vertical-align: middle;" << endl;
	content << "  text-decoration: none;" << endl;
	content << "  display: inline-block;" << endl;
	content << "  font-family: Arial, sans-serif;" << endl;
	content << "  cursor: pointer;" << endl;
	content << "}" << endl;
	content << ".button-home {transform: rotate(180deg); font-size: 26px;}" << endl;
	content << ".button-reload {margin-left: 30px; transform: rotate(90deg); font-size: 32px; font-weight: bold;}" << endl;
	content << ".table-name {" << endl;
	content << "  margin-left: 5px;" << endl;
	content << "  font-size: 26px;" << endl;
	content << "  display: inline-block;" << endl;
	content << "  vertical-align: middle;" << endl;
	content << "  font-weight: bold;" << endl;
	content << "}" << endl;
	content << "</style>" << endl;
	content << "</head>" << endl;
	content << "<body>" << endl;
	content << "<a href=" << HTML_INFO_PATH << " class=\"button button-home\" title=\"Back\">&#10140;</a>" << endl;
	content << "<label class=\"table-name\">" << title << "</label>" << endl;
	content << "<a onClick=\"window.location.reload();\" class=\"button button-reload\" title=\"Reload\">&#8635;</a>" << endl;
	content << "<h3>" << "SMTP client service: " << state << "</h3>" << endl;
	content << "<h3 style=\"margin-bottom: 0.2em;\">" << "SMTP statistics:" << "</h3>" << endl;
	content << "<table style=\"width:40%\">" << endl;
	content << nS->smtp->htmlStats();
	content << "</table>" << endl;
	content << "<h3 style=\"margin-bottom: 0.2em;\">" << "SMTP errors:" << "</h3>" << endl;
	content << "<table style=\"width:20%; text-align:left\">" << endl;
	content << errTable;
	content << "</table>" << endl;
	content << "</body>" << endl;
	content << "</html>" << endl;
	return content.str();
}
// Image loader function
string imgLoader(void *, string path, string, string)
{
	auto it = siteImages.find(path);
	if( it != siteImages.end() )
		return string(it->second.first, it->second.second);
	else
		return "";
}
// Web manifest function
string webManifest(void *, string path, string, string)
{
	stringstream ss;
	string manifest;
	ss << "{" << endl;
	ss << "	\"name\":\"Subnet Monitor\"," << endl;
	ss << "	\"short_name\":\"SNMonitor\"," << endl;
	ss << "	\"icons\": [{" << endl;
	ss << "		\"src\":\"/android-chrome-192x192.png\"," << endl;
	ss << "		\"sizes\":\"192x192\",\"type\":\"image/png\"" << endl;
	ss << "	},{" << endl;
	ss << "		\"src\":\"/android-chrome-512x512.png\"," << endl;
	ss << "		\"sizes\":\"512x512\",\"type\":\"image/png\"" << endl;
	ss << "	}]," << endl;
	ss << "	\"theme_color\":\"#FFFFFF\"," << endl;
	ss << "	\"background_color\":\"" << PAGE_BG_COLOR << "\"," << endl;
	ss << "	\"display\":\"standalone\"" << endl;
	ss << "}" << endl;
	manifest = ss.str();
	return manifest;
}


