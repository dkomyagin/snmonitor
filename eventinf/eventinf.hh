//============================================================================
// Name        : eventinf.hh
// Author      : Dmitry Komyagin
// Version     : 0.5
// Created on  : Oct 31, 2024
// Copyright   : Public domain
// Copyright   :
// Description : Header file for Event Informer library, Linux, ISO C++14
//============================================================================

#ifndef EVENTINF_HH_
#define EVENTINF_HH_

#include <atomic>

// Event information data structure
struct eventData
{
	std::string module  = "";
	std::string routine = "";
	std::string message = "";
	int16_t type = 0;
	std::string file    = "";
};
// Basic event informer class definition
class eventInformer
{
protected:
    std::atomic<uint32_t> verbose = {0};
public:
	// Destructor
	virtual ~eventInformer() {};
	// Set verbosity level
	void setVerbosityLvl(const uint32_t vlvl) { verbose = vlvl; };
    // Get verbosity level
    const uint32_t getVerbosityLvl() const { return verbose; };
	// Event information handler
	virtual void onEvent(const eventData &info) {};
};

// Simple event informer
class stdEventInformer: public eventInformer
{
public:
	// Outputs event information to console
	void onEvent(const eventData &info) override;
};

#endif /* EVENTINF_HH_ */
