//============================================================================
// Name        : eventinf.cpp
// Author      : Dmitry Komyagin
// Version     : 0.5
// Created on  : Oct 31, 2024
// Copyright   : Public domain
// Description : Event Informer library, Linux, ISO C++14
//============================================================================

#include <iostream>
#include "eventinf.hh"

using namespace std;

// Class 'stdEventInformer' methods
// Outputs event information to console
void stdEventInformer::onEvent(const eventData &info)
{
	if(info.message == "")
	{
		cout << info.module + "::" + info.routine + ": no message provided\n";
	}
	else if(info.type < 0)
	{
		cerr << info.module + "::" + info.routine + ": " + info.message +"\n";
	}
	else
	{
		cout << info.message +"\n";
	}
}
