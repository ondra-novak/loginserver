/*
 * session.h
 *
 *  Created on: Feb 12, 2018
 *      Author: ondra
 */

#pragma once
#include <string>

#include "shared/stringview.h"



class Session {
public:

	enum Status {
		valid = 0,
		invalid = 1,
		expired = 2
	};


	struct Info {

		///time when session has been created
		time_t created;
		///time when session becomes invalid (expires)
		time_t expires;
		///time when session is no longer extendible
		time_t extend;
		///user identifier;
		std::string userid;
	};


	Status unpackSession(ondra_shared::StrViewA sessionStr, Info &nfo);
    std::string packSession(const Info &info);

	Session(const std::string &secret);


protected:

	std::string secret;
};


