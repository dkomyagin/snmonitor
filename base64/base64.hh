//============================================================================
// Name        : base64.hh
// Author      : Dmitry Komyagin
// Version     : 1.0
// Created on  : Oct 14, 2024
// Copyright   : Public domain
// Description : Header file for BASE64 library, Linux, ISO C++11
//============================================================================

#ifndef BASE64_HH_
#define BASE64_HH_

#include <iostream>

std::string encode_base64(const char* text, size_t count);
std::string encode_base64(const std::string& text);
// RFC 4616
std::string SMTP_AUTH_PLAIN_encoder(const std::string& identity, const std::string& username, const std::string& password);
std::string decode_base64(const std::string&  enc_text);

#endif /* BASE64_HH_ */
