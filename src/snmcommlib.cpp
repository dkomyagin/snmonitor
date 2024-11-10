//======================================================================================
// Name        : snmcommlib.cpp
// Author      : Dmitry Komyagin
// Version     : 0.2
// Created on  : Oct 14, 2024
// Copyright   : Public domain
// Description : SNMONITOR common library, Linux, ISO C++14
//======================================================================================

#include "snmcommlib.hh"

using namespace std;

// Returns local time
string getLocalTime()
{
    time_t rawtime;
    char buffer[32] = {0};

    time(&rawtime);
    strftime(buffer, 32, "%F %T", localtime(&rawtime) );

    return string(buffer);
}
// Returns UTC time
string getUTCtime()
{
	time_t rawtime;
	char buffer[32] = {0};

	time(&rawtime);
	strftime(buffer, 32, "%F %T", gmtime(&rawtime) );

	return string(buffer);
}


