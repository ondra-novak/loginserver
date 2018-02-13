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
		time_t refreshExpireTime;
		Value userId;
		Value payload;
	};

	enum Status {
		valid = 0,
		invalid = 1,
		expired = 2
	};

	///Sets default expire time in seconds
	void setExpireTime(std::size_t t);
	///Sets default refresh expire time in seconds
	void setRefreshExpireTime(std::size_t t);

	///Creates user token
	/**
	 * @param userId user identification
	 * @return token
	 *
	 * @note the class must be initialized with private key
	 */
	String create(Value userId, Value payload = Value());

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


	///Refresh token
	/**
	 * creates new token which has updated expiration data
	 * @param info parsed token info (see parse() )
	 * @param revokeTime timestamp of last "revoke all tokens" function. If the token is created before
	 * this timestamp, function fails, because token has been revoked
	 * @retval string string of new token
	 * @retval empty failure, token is expired or revoked
	 *
	 * @note the class must be initialized with private key
	 *
	 */
	String refresh(Info &info, time_t revokeTime);

	typedef time_t (*TimeSource)();

	static time_t defaultTimeSource();


protected:
	size_t expiration = 300;
	size_t refreshExpiration = 0;
	TimeSource timeSource = &defaultTimeSource;

	Value info2json(const Info &info);
	void json2info(const Value v, Info &info);
};

} /* namespace loginsrv */

#endif /* SRC_TOKEN_USERTOKEN_H_ */
