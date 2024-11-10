//============================================================================
// Name        : httpnanosrv.cpp
// Author      : Dmitry Komyagin
// Version     : 1.03
// Created on  : Oct 28, 2024
// Copyright   : Public domain
// Description : HTTP nano server, Linux, ISO C++14
//============================================================================

#include "httpnanosrv.h"
#include "httpnanosrv.hh"
using namespace std;

//
static string getIMFfixdate(const int time_shift_sec = 0) // time shift in seconds
{
    time_t rawtime;
    char buffer[30] = {0};

    time(&rawtime);
    rawtime += time_shift_sec;
    strftime( buffer, 30, "%a, %d %b %Y %T GMT", gmtime(&rawtime) );

    return string(buffer);
}
// 'struct httpReplyOptions' constructor
httpReplyOptions::httpReplyOptions()
{
	rqMethod = HTTP_GET;
	statusCode = 0;
	contentType = STD_CONTENT_TYPE;
	modified_date = getIMFfixdate();
	cache_max_age = 0;
	connection = "";
}
// Request parser
static int parseHTTPrequest(const char *buffer,  struct httpRequestHeader *reqHeader)
{
    stringstream message;
    string line;
    smatch sm;
    httpFields field;

    static const regex eContol = regex("(GET|HEAD) +([^\\?|^#]+)[\\?]?([^#]*)#?(.*) +HTTP/(\\d\\.?\\d?)[\\S|\\s]*", regex_constants::icase);
    static const regex eField  = regex("([^:]+): ?(.+)\\s*");

    if( (toupper(buffer[0]) == 'G') or (toupper(buffer[0]) == 'H') )
    {
        message << buffer;
        getline(message, line);
        if( regex_match(line, sm, eContol) )
        {
            reqHeader->method   = toupper(buffer[0]) == 'G' ? HTTP_GET : HTTP_HEAD;
            reqHeader->path     = sm[2];
            reqHeader->query    = sm[3];
            reqHeader->fragment = sm[4];
            reqHeader->version  = sm[5];
        }
        else return -1; // error

        reqHeader->fields.clear();

        while( getline(message, line) )
        {
            if( (line == "\r") or (line == "") ) break; // end of header fields
            if( regex_match(line, sm, eField) )
            {
                field.name  = sm[1];
                field.token = sm[2];
                reqHeader->fields.push_back(field);
            }
        }
    }
    else
    {
        return -1;// error
    }
    return 0;
}
//
static string makeHTTPheader(vector<struct httpFields> fields)
{
    string header;

    for(auto it:fields)
    {
        header += it.name + ": " + it.token + "\r\n";
    }
    header += "\r\n";
    return header;
}

// Class 'httpNanoServer' methods
// Constructor
httpNanoServer::httpNanoServer(in_port_t httpPort, const html_pages_t &sitePages, eventInformer *eventInf)
{
	startTime = getIMFfixdate();
	srvPort = httpPort;
	htmlPages = sitePages;
	if(eventInf == nullptr)
	{
		self_ei = true;
		ei = new stdEventInformer();
	}
	else
	{
		self_ei = false;
		ei = eventInf;
	}

	thread listener(&httpNanoServer::httpListener, this);
	listener.detach();

	while(!_srv_init_flag) this_thread::yield(); // waiting for thread to be initialized
}
// Destructor
httpNanoServer::~httpNanoServer()
{
	_runFlag = false;
	shutdown(srv_sd, SHUT_RDWR);
	close(srv_sd);
	while(!_srv_exit_flag) this_thread::yield(); // waiting for listener termination
	for( int sd:peer_sockets )
	{
		shutdown(sd, SHUT_RDWR);
		close(sd);
	}
	while( !peer_sockets.empty() ) this_thread::yield(); // waiting for workers termination
	if(self_ei) delete ei;
}
// Returns boolean value that indicates whether httpNanoServer is stated
bool httpNanoServer::isStarted() const
{
	return (_srv_init_flag and !_srv_exit_flag);
}
// Returns server start time
string httpNanoServer::getStartTime() const
{
	return startTime;
}
// Returns number of active connections
size_t httpNanoServer::getActiveConnections()
{
	lock_guard<mutex> lck(ps_mtx);
	return peer_sockets.size();
}
// Returns content type based on extension
string httpNanoServer::contentTypeByExt(string path)
{
	string ctype = "";
	smatch sm;
	static const map<string, string> contentType =
	{
		{ ".gif",  "image/gif" },
		{ ".jpg",  "image/jpeg" },
		{ ".png",  "image/png" },
		{ ".tiff", "image/tiff" },
		{ ".ico",  "image/x-icon" },
		{ ".djvu", "image/vnd.djvu" },
		{ ".svg",  "image/svg+xml" },
		{ ".webmanifest", "application/manifest+json"}
	};
	static const regex e = regex("[^\\.]+(\\.[^\\.]*$)", regex_constants::icase);

	if( (path.size() > 2) and regex_search(path, sm, e) )
	{
		auto it = contentType.find(sm[1]);
		if( it != contentType.end() ) ctype = it->second ;
	}
	return ctype;
}
// HTTP reply 304
string httpNanoServer::httpReply304()
{
	struct httpReplyOptions options;
	options.statusCode = HTTP_STATUS_NOT_MODIFIED;
	return makeHTTPreply("", options);
}
// HTTP reply 400
string httpNanoServer::httpReply400()
{
	struct httpReplyOptions options;
	options.statusCode = HTTP_STATUS_BAD_REQUEST;
	return makeHTTPreply("", options);
}
// HTTP reply 404
string httpNanoServer::httpReply404()
{
	stringstream content;
	struct httpReplyOptions options;
	options.statusCode = HTTP_STATUS_NOT_FOUND;

	content << "<html>" << endl;
	content << "<head><title>404 Not Found</title></head>" << endl;
	content << "<body>" << endl;
	content << "<center><h1>404 Not Found</h1></center>" << endl;
	content << "<hr><center>" << HTTP_SERVER_NAME << "</center>" << endl;
	content << "</body>" << endl;
	content << "</html>" << endl;

	return makeHTTPreply(content.str(), options);
}
// HTTP reply 408
string httpNanoServer::httpReply408()
{
	struct httpReplyOptions options;
	options.statusCode = HTTP_STATUS_REQUEST_TIMEOUT;
	return makeHTTPreply("", options);
}
// HTTP reply 503
string httpNanoServer::httpReply503()
{
	stringstream content;
	struct httpReplyOptions options;
	options.statusCode = HTTP_STATUS_SERVICE_UNAVAILABLE;

	content << "<html>" << endl;
	content << "<head><title>503 Service Unavailable</title></head>" << endl;
	content << "<body>" << endl;
	content << "<center><h1>503 Server Busy</h1></center>" << endl;
	content << "<hr><center>" << HTTP_SERVER_NAME << "</center>" << endl;
	content << "</body>" << endl;
	content << "</html>" << endl;

	return makeHTTPreply(content.str(), options);
}
// Incoming connections listener
void httpNanoServer::httpListener()
{
	struct sockaddr_in peer_sa, srv_sa = {0};
	socklen_t peer_sa_len;
	int peer_sd;
	string replyMessage;
	struct eventData edata = {HTTP_NS_MODULE_NAME, "httpListener()", "", 0};

	srv_sa.sin_family = AF_INET;
	srv_sa.sin_addr.s_addr = INADDR_ANY;
	srv_sa.sin_port = htons(srvPort);

	// Creating socket file descriptor
	srv_sd = socket( AF_INET, SOCK_STREAM, IPPROTO_IP);
	if(srv_sd == -1)
	{
		edata.message = "Failed to create server socket descriptor: " + string( strerror(errno) );
		edata.type = HTTP_NS_ERROR_SOCKET;
		ei->onEvent(edata);
		_srv_exit_flag = true;
		_srv_init_flag = true;
		return;
	}
	else
	{
		if(bind( srv_sd, (struct sockaddr *) &srv_sa, sizeof(struct sockaddr_in) ) == -1)
		{
		    close(srv_sd);
		    edata.message = "Failed to bind: " + string( strerror(errno) );
		    edata.type = HTTP_NS_ERROR_BIND;
		    ei->onEvent(edata);
		    _srv_exit_flag = true;
		    _srv_init_flag = true;
		    return;
		}
		else
		{
			if(listen(srv_sd, MAX_SRV_QUEUE) == -1)
			{
				close(srv_sd);
				edata.message = "Failed to start listening: " + string( strerror(errno) );
				edata.type = HTTP_NS_ERROR_LISTEN;
				ei->onEvent(edata);
				_srv_exit_flag = true;
				_srv_init_flag = true;
			    return;
			}
		}
	}
	struct linger so_linger;
	so_linger.l_onoff = true;
	so_linger.l_linger = 0;
	if(setsockopt( srv_sd, SOL_SOCKET, SO_LINGER, &so_linger, sizeof(struct linger) ) == -1) // avoid TIME_WAIT on closing socket
	{
		edata.message = "Failed to set socket option: " + string( strerror(errno) );
		edata.type = HTTP_NS_ERROR_OPTION;
		ei->onEvent(edata);
	}
	// End of init stage
	_srv_init_flag = true;
	// Service started
	edata.message = "HTTP server listens on port " + to_string(srvPort);
	edata.type = HTTP_NS_STARTED;
	ei->onEvent(edata);

	while(_runFlag)
	{
		peer_sa_len = sizeof(struct sockaddr_in);
		memset(&peer_sa, 0, peer_sa_len);
		peer_sd = accept( srv_sd, (struct sockaddr *) &peer_sa, &peer_sa_len );
		if(peer_sd != -1)
		{
			if(getActiveConnections() < MAX_SRV_CONNECTIONS)
			{
				ps_mtx.lock();
				peer_sockets.insert(peer_sd);
				ps_mtx.unlock();
			}
			else
			{
				++srvStats.reject_err_cnt;
				replyMessage = httpReply503(); // 503 server busy - too many connections
				if(_runFlag) send(peer_sd, replyMessage.c_str(), replyMessage.length(), MSG_NOSIGNAL);
				close(peer_sd);
				continue;
			}
		}
		else
		{
			if(_runFlag)
			{
				++srvStats.accept_err_cnt;
				edata.message = "Failed to create peer socket descriptor: " + string( strerror(errno) );
				edata.type = HTTP_NS_ERROR_PEER;
				ei->onEvent(edata);
			}
			continue;
		}
		// Setup a connection
		if(_runFlag)
		{
			thread worker(&httpNanoServer::httpWorker, this, peer_sd);
			worker.detach();
		}
		else
		{
			close(peer_sd);
			break;
		}
	} // end while
	close(srv_sd);
	edata.message = "Service 'httpListener' stopped";
	edata.type = HTTP_NS_STOPPED;
	ei->onEvent(edata);
	_srv_exit_flag = true;
}
// Requests handler
void httpNanoServer::httpWorker(const int socket)
{
	long lr = 0, ls = 1;
	struct httpRequestHeader reqHeader;

	char buffer[30000] = {0};
	string replyMessage, htmlPage;
	struct eventData edata = {HTTP_NS_MODULE_NAME, "httpWorker()", "", 0};
	hash<string> hasher;
	map<string, size_t> htmlPageHash;
	size_t phash;

	struct timeval tv = {0};
	tv.tv_sec = HTTP_CONNECTION_MAX_IDLE_TIME;
	if(setsockopt( socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv) ) == -1)
	{
		edata.message = "Failed to set timeout option: " + string( strerror(errno) );
	    edata.type = HTTP_NS_ERROR_TIMEOUT;
	    ei->onEvent(edata);
	}

	while(_runFlag)
	{
		memset( buffer, 0, sizeof(buffer) );
		lr = read( socket , buffer, sizeof(buffer) );
		if(lr <= 0) break; // error, timeout or connection closed
		if( (toupper(buffer[0]) == 'G') or (toupper(buffer[0]) == 'H') ) // GET or HEAD methods (probably)
		{
			if(parseHTTPrequest(buffer, &reqHeader) == 0)
			{
				//cout << "Method: " << (int) reqHeader.method << endl;
				//cout << "Path: " << reqHeader.path << endl;
				//cout << "Query: " << reqHeader.query << endl;
				//cout << "Fragment: " << reqHeader.fragment << endl;

				replyMessage = "";

				if( htmlPages.find(reqHeader.path) != htmlPages.end() ) // page exists
				{
					if(_runFlag)
					{
						struct httpReplyOptions options;

						options.rqMethod = reqHeader.method;
						options.statusCode = HTTP_STATUS_OK;
						options.cache_max_age = htmlPages[reqHeader.path].second;
						options.connection = "keep-alive";

						string ctype = contentTypeByExt(reqHeader.path); // content type by file extension

						if(ctype != "") options.contentType = ctype;

						htmlPage = htmlPages[reqHeader.path].first(this, reqHeader.path, reqHeader.query, reqHeader.fragment);
						phash = hasher(htmlPage); // calculate hash of the page

						if( htmlPageHash.find(reqHeader.path) != htmlPageHash.end() )
						{
							for(auto field: reqHeader.fields)
							{
								if(field.name == "If-Modified-Since")
								{
									// check if page was modified
									if(htmlPageHash[reqHeader.path] == phash) replyMessage = httpReply304(); // 304 Not Modified
								}
							}
						}
						else
						{
							htmlPageHash.insert( {reqHeader.path, phash} );
							replyMessage = makeHTTPreply(htmlPage, options);
						}
						if(replyMessage == "")
						{
							htmlPageHash[reqHeader.path] = phash; // update hash
							replyMessage = makeHTTPreply(htmlPage, options);
						}
					}
				}
				else
				{
					replyMessage = httpReply404(); // 404 Not found
				}
			}
			else
			{
				replyMessage = httpReply400(); // parsing error - 400 Bad request
			}
		}
		else
		{
			replyMessage = httpReply400(); // request error or method not allowed - 400 Bad request
		}

		if(_runFlag) ls = send(socket, replyMessage.c_str(), replyMessage.length(), MSG_NOSIGNAL);
		if(ls <= 0) break; // error or connection closed
	} // end while
	if( _runFlag and (lr == -1) and (ls > 0) ) // request time out
	{
		replyMessage = httpReply408(); // 408 Request timeout
		ls = send(socket, replyMessage.c_str(), replyMessage.length(), MSG_NOSIGNAL);
	}
	close(socket);
	lock_guard<mutex> lck(ps_mtx);
	peer_sockets.erase(socket);
}
// Create HTTP reply
string httpNanoServer::makeHTTPreply(string content, struct httpReplyOptions options)
{
	string header, replyMessage = content;
	vector<struct httpFields> fields;
	string cache_control;

	header = "HTTP/1.1 " + to_string(options.statusCode) + " " + httpStatusCodes.at(options.statusCode) + "\r\n";

	if(options.cache_max_age > 0)
		cache_control = "max-age=" + to_string(options.cache_max_age);
	else
		cache_control = "no-cache";

	fields.push_back( {"cache-control", cache_control} );
	fields.push_back( { "Content-Length", to_string( replyMessage.size() ) } );
	fields.push_back( { "Content-Type", options.contentType.c_str() } );
	fields.push_back( { "Date", getIMFfixdate() } );
	fields.push_back( { "Expires", getIMFfixdate(options.cache_max_age) } );
	fields.push_back( {"Last-Modified", options.modified_date} );
	fields.push_back( {"Server", HTTP_SERVER_NAME} );
	if(options.connection != "") fields.push_back( {"Connection", options.connection} );

	header += makeHTTPheader(fields);
	if(options.rqMethod == HTTP_GET)
		replyMessage = header + replyMessage;
	else
		replyMessage = header; // A response to a HEAD method should not have a body
	return replyMessage;
}
