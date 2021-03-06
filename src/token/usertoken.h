/*
 * usertoken.h
 *
 *  Created on: 13. 2. 2018
 *      Author: ondra
 */


#ifndef SRC_TOKEN_USERTOKEN_H_
#define SRC_TOKEN_USERTOKEN_H_
#pragma once

#include "token.h"

namespace loginsrv {

class UserToken: public Token {
public:
	using Token::Token;


	struct Info {
		time_t created;
		time_t expireTime;
		Value purpose; //purpose
		Value userId;
		Value roles; //roles defined by a user profile
	};

	enum Status {
		valid = 0,
		invalid = 1,
		expired = 2
	};


	Info prepare(Value userId, const Value &purpose, const Value &roles, unsigned int expire_s);


	String create(const Info &info);

	///Parses user token
	/**
	 *
	 * @param token token
	 * @param info parsed data
	 * @retval valid token is valid
	 * @retval invalid token is invalid and was not parsed (info is untouched)
	 * @retval expired token is expired. Structure info is filled
	 */
	Status parse(const StrViewA token, Info &info);


	Value check(const StrViewA &token, const StrViewA &purpose, const StrViewA &role = StrViewA());
	Value check(const StrViewA &token, const StringView<StrViewA> &listPurposes, const StrViewA &role = StrViewA());

	static Value checkRole(const Info &info, const StrViewA &role);

	typedef time_t (*TimeSource)();

	static time_t defaultTimeSource();


protected:
	TimeSource timeSource = &defaultTimeSource;

	Value info2json(const Info &info);
	void json2info(const Value v, Info &info);
};

} /* namespace loginsrv */

#endif /* SRC_TOKEN_USERTOKEN_H_ */
