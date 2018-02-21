/*
 * usertoken.cpp
 *
 *  Created on: 13. 2. 2018
 *      Author: ondra
 */

#include "usertoken.h"

namespace loginsrv {




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
		info.userId,
		info.purpose,
		info.roles};
}

Value UserToken::checkRole(const Info &info, const StrViewA &role) {
	if (!role.empty()) {
		for (Value v : info.roles) if (v.getString() == role) return info.userId;
		return Value();
	} else {
		return info.userId;
	}
}

Value UserToken::check(const StrViewA &token, const StrViewA &purpose, const StrViewA &role ) {
	Value userId;
	Info info;
	if (parse(token, info)) return userId;
	if (info.purpose.type() == json::array) {
		for (Value a: info.purpose) if (a.getString() == purpose) return checkRole(info, role);
	}else {
		if (purpose == info.purpose.getString()) return checkRole(info,role);
	}
	return Value();

}

Value UserToken::check(const StrViewA &token, const StringView<StrViewA> &listPurposes, const StrViewA &role ) {
	Info info;
	Value userId;
	if (parse(token, info)) return userId;

	for (auto &&x: listPurposes) {

		if (info.purpose.type() == json::array) {
			for (Value a: info.purpose) if (a.getString() == x) return checkRole(info,role);
		}else {
			if (x== info.purpose.getString()) return checkRole(info,role);
		}
	}
	return Value();
}

UserToken::Info UserToken::prepare(Value userId, const Value &purpose, const Value &roles, unsigned int expire_s) {
	Info nfo;
	nfo.created = timeSource();
	nfo.expireTime = nfo.created+expire_s;
	nfo.userId= userId;
	nfo.purpose = purpose;
	nfo.roles = roles;
	return nfo;
}


void UserToken::json2info(const Value v, Info& info) {
	info.created = v[0].getUInt();
	info.expireTime = v[1].getUInt()+ info.created;
	info.userId = v[2];
	info.purpose = String(v[3]);
	info.roles = v[4];
}

time_t UserToken::defaultTimeSource() {
	time_t now;
	time(&now);
	return now;

}


} /* namespace loginsrv */

