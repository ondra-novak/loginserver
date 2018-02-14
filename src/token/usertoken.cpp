/*
 * usertoken.cpp
 *
 *  Created on: 13. 2. 2018
 *      Author: ondra
 */

#include "usertoken.h"

namespace loginsrv {


void UserToken::setExpireTime(std::size_t t) {
	expiration = t;
}

void UserToken::setRefreshExpireTime(std::size_t t) {
	refreshExpiration = t;
}


String UserToken::create(Value userId, Value payload) {

	Info info;
	prepare(userId, info);
	info.payload = payload;
	return create(info);
}

void UserToken::prepare(Value userId, Info &info) {
	auto now = timeSource();;
	info.userId = userId;
	info.created = now;
	info.expireTime = now+expiration;
	info.refreshExpireTime = now+refreshExpiration+expiration;
}

String UserToken::create(const Info &info) {
	Value v = info2json(info);
	return Token::createToken(v);
}

UserToken::Status UserToken::parse(const StrViewA token, Info& info) {
	Value v = Token::parseToken(token);
	if (v.defined()) {

		json2info(v, info);
		auto now = timeSource();
		if (info.expireTime < now) return expired;
		else return valid;

	} else {
		return invalid;
	}
}


Value UserToken::info2json(const Info& info) {
	return {
		(std::uintptr_t)info.created,
		(std::uintptr_t)(info.expireTime-info.created),
		(std::uintptr_t)(info.refreshExpireTime-info.expireTime),
		info.userId,
		info.payload};
}

String UserToken::refresh(Info& info, time_t revokeTime) {
	auto now = timeSource();
	if (info.refreshExpireTime < now) return String();
	if (info.created < revokeTime) return String();
	info.expireTime = now+expiration;
	info.refreshExpireTime=now+refreshExpiration;
	return Token::createToken(info2json(info));
}

void UserToken::json2info(const Value v, Info& info) {
	info.created = v[0].getUInt();
	info.expireTime = v[1].getUInt()+ info.created;
	info.refreshExpireTime = v[2].getUInt()+info.expireTime;
	info.userId = v[3];
	info.payload = v[4];
}

time_t UserToken::defaultTimeSource() {
	time_t now;
	time(&now);
	return now;

}


} /* namespace loginsrv */

