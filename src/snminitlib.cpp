//============================================================================
// Name        : snminitlib.cpp
// Author      : Dmitry Komyagin
// Version     : 0.6
// Created on  : Oct 30, 2024
// Copyright   : Public domain
// Description : SNMONITOR init library, Linux, ISO C++14
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

#include "snminitlib.hh"

using namespace std;

// Output help message to console
void coutHelpMessage()
{
	stringstream outmssg;
	outmssg << "Usage:" << endl;
	outmssg << "  sudo snmonitor [-h] [-d path] [-p number] [-6] [-u|-uv filename]" << endl;
	outmssg << "Options:" << endl;
	outmssg << "  -h" << "\t\t" << "to show this help" << endl;
	outmssg << "  -d path" << "\t" << "to set working directory" << endl;
	outmssg << "  -p number" << "\t" << "to set HTTP server port (default: " << APP_DEFAULT_HTTP_PORT << ", 0 to disable)" << endl;
	outmssg << "  -6" << "\t\t" << "to enable IPv6 functionality" << endl;
	outmssg << "  -u filename" << "\t" << "to upload MAC vendor CSV database" << endl;
	outmssg << "  -uv filename" << "\t" << "to upload MAC vendor CSV database in verbose mode" << endl;
	outmssg << "Download MAC vendor CSV database from: http://maclookup.app/downloads/csv-database" << endl;
	cout << outmssg.str();
	return;
}
// Set working directory
static int setWorkingDir(const char *path, const char *err_mssg)
{
	int rc;
	rc = chdir(path);
	if( rc != 0 ) perror(err_mssg);
	return rc;
}
// Search in options
int searchOptions(int argc, char* argv[], const char *opt)
{
	for( uint8_t idx = 1; idx < argc; idx++ )
		if(strcmp( argv[idx], opt) == 0) return idx;
	return -1;
}
// String to port number conversion, returns -1 on any errors
static int getIPport(string  cstr)
{
	unsigned long s;
	try
	{
		s = stoul(cstr);
	    if(s > 65535) throw out_of_range("getIPport");
	}
	catch(...)
	{
		s = -1;
	}
	return (int) s;
}
// String to verbosity level conversion, returns -1 on any errors
static int getVerbosityLvl(string  cstr)
{
    unsigned long s;
    try
    {
        s = stoul(cstr);
        if(s > 255) throw out_of_range("getVerbosityLvl");
    }
    catch(...)
    {
        s = -1;
    }
    return (int) s;
}
// Init file parsing
static int parseInit(fstream& fs, cfgdict& config)
{
	string line, sname, key, val;
	smatch sm;
	dict section;
	bool bflag = true;
	int syntax_err = 0;

	while( getline(fs, line) )
	{
		if( (line.size() == 0) or (line[0] == ';') or (line[0] == '#') ) continue; // comment or empty line
		line = regex_replace(line, regex("^\\s+"), ""); // trim leading whitespaces
		if(line.size() == 0) continue; // whitespaces only (empty) line
		if(line[0] == '[')
		{
			regex_match( line, sm, std::regex("\\[([^;#\\s]+)\\]\\s*") );
			if(sm.size() == 2)
			{
				if(bflag)
				{
					sname = sm[1];
					transform(sname.begin(), sname.end(), sname.begin(), ::tolower);
					bflag = false;
				}
				else
				{
					config.insert( {sname, section} );
					section.clear();
					sname = sm[1];
					transform(sname.begin(), sname.end(), sname.begin(), ::tolower);
				}
			}
			else
			{
				++syntax_err;
				if(!bflag)
				{
					config.insert( {sname, section} );
					section.clear();
					bflag = true;
				}
			}
			continue;
		}
		else if(bflag)
		{
			++syntax_err;
			continue;
		}
		else
		{
			regex_match( line, sm, std::regex("([^;#\\s]+)\\s*=\\s*(.*[^\\s]+)\\s*") );

			if(sm.size() == 3)
			{
				key = sm[1];
				val = sm[2];
				transform(key.begin(), key.end(), key.begin(), ::tolower);
				section.insert( {key, val} );
			}
			else
				++syntax_err;
		}
	}
	config.insert( {sname, section} );
	return syntax_err;
}
// Init file processing
int initFileProc(string initFile, struct initVars *initv)
{
	int rc, port;
	string val;
	fstream fs;
	cfgdict config;

	// Open file
	fs.open(initFile, ios::in);
	if( !fs.is_open() )
	{
		cout << "Init file '" +  initFile + "' not found\n";
		return -1;
	}
	cout << "Using init file '" +  initFile + "'\n";

	// Parse init file
	rc = parseInit(fs, config);
	fs.close();

	if(rc) cerr << "Init file warning: Syntax errors: " << rc << endl;

	// Process options

	// [app]
	if(config["app"]["ipv6"] == "yes") initv->ipv6 = true;

	val = config["app"]["workdir"];
	if( val.size() )
	{
		if( (val[0] == '\'') or  (val[0] == '"') ) val.erase( 0, 1 );
		if( (val[val.size() - 1] == '\'') or (val[val.size() - 1] == '"') ) val.erase( val.size() - 1 );

		rc = setWorkingDir( val.c_str(), "Init file warning: Setting working directory failure" );
	}
	// [http]
	val = config["http"]["port"];
	if( val.size() and (val != "default")  )
	{
		port = getIPport(val);
		if(port == -1)
		{
			cerr << "Init file warning: Setting HTTP port failure: Value out of range or invalid\n";
		}
		else
		{
			initv->httpPort = (in_port_t) port;
		}
	}
	// [smtp]
	val = config["smtp"]["notify"];
	if( (val == "yes") or (val == "true") ) initv->notify = true;
	if(initv->notify)
	{
		val = config["smtp"]["server"];
		if(val != "")
			initv->smtpData.srv = val;
		else
		{
			initv->notify = false;
			cerr << "Init file error: Setting SMTP server failure: Value not set\n";
		}
	}
	if(initv->notify)
	{
		val = config["smtp"]["port"];
		if( val.size() )
		{
			port = getIPport(val);
			if(port == -1)
			{
				initv->notify = false;
				cerr << "Init file error: Setting SMTP port failure: Value out of range or invalid\n";
			}
			else
			{
				initv->smtpData.port = val;
			}
		}
		else
		{
			initv->notify = false;
			cerr << "Init file error: Setting SMTP port failure: Value not set\n";
		}
	}
	if(initv->notify)
	{
		val = config["smtp"]["sender"];
		if( val.size() )
			initv->smtpData.sndr = val;
		else
		{
			initv->notify = false;
			cerr << "Init file error: Setting SMTP sender failure: Value not set\n";
		}
	}
	if(initv->notify)
	{
		val = config["smtp"]["recipients"];
		if( val.size() )
			initv->smtpData.rcpts = val;
		else
		{
			initv->notify = false;
			cerr << "Init file error: Setting SMTP recipients failure: Value not set\n";
		}
	}
    if(initv->notify)
    {
        val = config["smtp"]["verbose"];
        if( val.size() )
        {
           int vlvl = getVerbosityLvl(val);
           if(vlvl != -1) initv->smtpVerbose = (uint8_t) vlvl;
        }
    }
	// [smtp][tls]
	if(initv->notify)
	{
		val = config["smtp"]["tls"];
		if( (val == "yes") or (val == "true") )
		{
			initv->smtpData.tls = true;
		}
		else
		{
			initv->smtpData.tls = false;
			if( initv->smtpData.port == to_string(SMTPS_PORT) )
			{
	            initv->notify = false;
	            cerr << "Init file error: Using SMTPS port requires TLS support to be enabled\n";
			}
		}
	}
	// [smtp][ssl_verify_server]
	if(initv->notify and initv->smtpData.tls)
	{
		val = config["smtp"]["ssl_verify_server"];
		if( ( val == "no" ) or ( val == "false" ) )
		{
			initv->smtpData.verify = false;
		}
		else
		{
			initv->smtpData.verify = true;
		}
	}
	// [smtp][username]
	if(initv->notify and initv->smtpData.tls)
	{
		val = config["smtp"]["username"];
		if( val.size() )
			initv->smtpData.username = val;
		else
		{
			initv->notify = false;
			cerr << "Init file error: Setting SMTP username failure: Value not set\n";
		}
	}
	// [smtp][password]
	if(initv->notify and initv->smtpData.tls)
	{
		val = config["smtp"]["password"];
		if( val.size() )
			initv->smtpData.password = val;
		else
		{
			initv->notify = false;
			cerr << "Init file error: Setting SMTP password failure: Value not set\n";
		}
	}
	return 0;
}
// Command line processing
// Return code: '-1' - terminate with EXIT_FAILURE; '0' - OK, go ahead; '1' - terminate with EXIT_SUCCESS
int clProc(int argc, char* argv[], struct initVars *initv, const char *db_file_name)
{
	int rc, idx;
	char cwd[PATH_MAX];
	sqlite3 *db;

	// Process options
	if(argc > 1)
	{
		// Search for "-d" option
		idx = searchOptions(argc, argv, "-d");
		if(idx != -1)
		{
			if( (idx + 1) >= argc )
			{
				cerr << "Command line error. Setting working directory failure: Too few arguments\n\n";
				coutHelpMessage();
				return -1;
			}
			else if(setWorkingDir( argv[idx + 1], "Command line error. Setting working directory failure" ) != 0)
			{
				return -1;
			}
		}
		// Search for "-p" option
		idx = searchOptions(argc, argv, "-p");
		if(idx != -1)
		{
			if( (idx + 1) >= argc )
			{
				cerr << "Command line error. Setting HTTP port failure: Too few arguments\n\n";
				coutHelpMessage();
				return -1;
			}
			else
			{
				int port =  getIPport( string(argv[idx + 1]) );
				if(port == -1)
				{
					cerr << "Command line error. Setting HTTP port failure: Value out of range or invalid\n";
					return -1;
				}
				else
				{
					initv->httpPort = (in_port_t) port;
				}
			}
		}
		// Search for "-6" option
		idx = searchOptions(argc, argv, "-6");
		if(idx != -1)
		{
			initv->ipv6 = true;
		}
		// Search for "-uv" or "-u" options
		bool verbose, upload = false;
		idx = searchOptions(argc, argv, "-uv");
		if(idx != -1 )
		{
			upload  = true;
			verbose = true;
		}
		else
		{
			idx = searchOptions(argc, argv, "-u");
			if(idx != -1)
			{
				upload  = true;
				verbose = false;
			}
		}
		if(upload)
		{
			if( (idx + 1) >= argc )
			{
				cerr << "Command line error. Uploading CSV file failure: Too few arguments\n\n";
				coutHelpMessage();
				return -1;
			}
			else
			{
				if(getcwd( cwd, sizeof(cwd) ) != NULL)
				{
					cout << "Current working directory: " << cwd << endl;
				}
				else
				{
					perror("Get current working directory error");
					return -1;
				}
				rc = initDB(db_file_name, &db);
				if(rc != SQLITE_OK)
				{
					cerr << "Database initializing failure, rc = " << rc << endl;
					return -1;
				}
				cout << "Uploading MAC vendor CSV database\n";
				rc = uploadMACvendors(db, argv[idx + 1], verbose);
				sqlite3_close(db);
				if(rc != SQLITE_OK)
				{
					cerr << "File '" << argv[idx + 1] << "' was not uploaded\n";
					return -1;
				}
				else
				{
					cout << "File '" << argv[idx + 1] << "' was successfully uploaded\n";
					return 1;
				}
			}
		}
	}
	return 0;
}
