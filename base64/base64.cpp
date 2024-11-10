//============================================================================
// Name        : base64.cpp
// Author      : Dmitry Komyagin
// Version     : 1.01
// Created on  : Nov 4, 2024
// Copyright   : Public domain
// Description : BASE64 library, Linux, ISO C++11
//============================================================================

#include <iostream>
#include <cstdint>
#include <cstring>

using namespace std;

static const char encode_table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
//
string encode_base64(const char* text, size_t count)
{
	uint32_t triplet;
	char *base64;
	size_t i, j = 0;
	size_t tnum = count/3;
	uint8_t mod = count%3;

	base64 = (char *) malloc(tnum*4 + ( mod ? 1 : 0 )*4 + 1);

	for(i=0; i < tnum; ++i)
	{
		triplet = text[i*3];
		triplet = triplet << 8;
		triplet = triplet | text[i*3 + 1];
		triplet = triplet << 8;
		triplet = triplet | text[i*3 + 2];
		base64[j++] = encode_table[triplet >> 18];
		base64[j++] = encode_table[(triplet >> 12) & 0x3F];
		base64[j++] = encode_table[(triplet >> 6) & 0x3F];
		base64[j++] = encode_table[triplet & 0x3F];
	}
	if(mod != 0)
	{
		triplet = text[tnum*3];
		triplet = triplet << 8;
		if(mod == 2) triplet = triplet | text[tnum*3 + 1];
		triplet = triplet << 8;
		base64[j++] = encode_table[triplet >> 18];
		base64[j++] = encode_table[(triplet >> 12) & 0x3F];
		if(mod == 2)
		{
			base64[j++] = encode_table[(triplet >> 6) & 0x3F];
		}
		else
		{
			base64[j++] = '=';
		}
		base64[j++] = '=';
	}
	base64[j] = '\0';

	string output = string(base64);
	free(base64);

	return output;
}
//
string encode_base64(const string& text)
{
	return encode_base64( text.c_str(), text.size() );
}
// RFC 4616
string SMTP_AUTH_PLAIN_encoder(const string& identity, const string& username, const string& password)
{
	if( (username.size() == 0) or (password.size() == 0) ) return ""; // username and password MUST be non-empty

	size_t j = 0;
	const size_t count = identity.size() + username.size() + password.size() + 2;
	char text[count];

	for(auto it:identity) text[j++] = it;
	text[j++] = '\0';
	for(auto it:username) text[j++] = it;
	text[j++] = '\0';
	for(auto it:password) text[j++] = it;
	return encode_base64(text, count);
}
//
string decode_base64(const string&  enc_text)
{
	size_t i, j = 0;
	char *ec;
	uint32_t triplet;
	char *text;
	size_t len = enc_text.size();
	size_t qnum = len/4;

	if( (len%4 != 0) or ( (enc_text[len - 2] == '=') and (enc_text[len - 1] != '=') ) ) return ""; // wrong base64 string
	text = (char *) malloc(qnum*3 + 1);

	for(i = 0; i < qnum; ++i)
	{
		ec = strchr( (char *) encode_table, enc_text[4*i] );
		if(ec == nullptr) return ""; // wrong symbol
		triplet = ec - encode_table;
		triplet = triplet << 6;
		ec = strchr( (char *) encode_table, enc_text[4*i + 1] );
		if(ec == nullptr) return ""; // wrong symbol
		triplet = triplet | (ec - encode_table);
		triplet = triplet << 6;
		if( not (i == (qnum - 1) and enc_text[4*i + 2] == '=') )
		{
			ec = strchr( (char *) encode_table, enc_text[4*i + 2] );
			if(ec == nullptr) return ""; // wrong symbol
			triplet = triplet | (ec - encode_table);
		}
		triplet = triplet << 6;
		if( not (i == (qnum - 1) and enc_text[4*i + 3] == '=') )
		{
			ec = strchr( (char *) encode_table, enc_text[4*i + 3] );
			if(ec == nullptr) return ""; // wrong symbol
			triplet = triplet | (ec - encode_table);
		}
		text[j++] = triplet >> 16;
		text[j++] = (triplet >> 8) & 0xFF;
		text[j++] = triplet & 0xFF;
	}
	text[j] = '\0';

	string output = string(text);
	free(text);

	return output;
}
