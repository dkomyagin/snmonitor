//======================================================================================
// Name        : snmcommlib.hh
// Author      : Dmitry Komyagin
// Version     : 0.3
// Created on  : Oct 27, 2024
// Copyright   : Public domain
// Description : Header file for SNMONITOR common library, Linux, ISO C++14
//======================================================================================

#ifndef SNMCOMMLIB_HH_
#define SNMCOMMLIB_HH_

#include <time.h>
#include <string>

// Returns local time
std::string getLocalTime();
// Returns UTC time
std::string getUTCtime();
// Converts characters to numbers. Returns 0 if character not a digit
inline int ch2int(const char ch)
{
    return (int) ( (ch > 48) and (ch < 58) ) ? (ch - '0') : 0;
}

#endif /* SNMCOMMLIB_HH_ */
