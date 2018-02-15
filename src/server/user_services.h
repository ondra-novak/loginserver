/*
 * user_services.h
 *
 *  Created on: Feb 13, 2018
 *      Author: ondra
 */

#ifndef USER_SERVICES_H_
#define USER_SERVICES_H_
#include <couchit/couchDB.h>
#include <couchit/document.h>
#include <imtjson/string.h>

namespace loginsrv {

using namespace couchit;
using namespace json;

class UserID: public String {
public:
	UserID() {}
	UserID(const Value &v):String(v) {}
	UserID(const String &v):String(v) {}
	UserID(const StrViewA &v):String(v) {}
};

class UserProfile: public Document {
public:

	static const int accessCodeLen = 7;
	static const int accessCodeSep = 4;
	static const int accessCodeTries = 3;

	using Document::Document;

	bool checkPassword(const StrViewA &password);
	bool checkOTP(unsigned int otpCode);

	void setPassword(const StrViewA &password);
	void enableOTP(const String &secret);
	void disableOTP();

	String genAccessCode(String purpose, std::size_t expire_tm);

	enum TryResult {
		///code accepted and removed
		accepted = 0,
		///code rejected, but state has been changed
		rejected = 1,
		///invalid request was invalid (no save needed)
		invalid = -1

	};

	TryResult tryAcccessCode(String purpose, String code);


	static Value calculatePasswordDigest(const StrViewA &salt, const StrViewA &password);
};


class UserServices {
public:
	UserServices(CouchDB &db);


	UserProfile createUser(const StrViewA &email);
	UserID findUser(const StrViewA &email) const;
	UserProfile loadProfile(const UserID &user);
	void storeProfile(UserProfile &profile);

protected:
	CouchDB &db;
};

} /* namespace loginsrv */

#endif /* USER_SERVICES_H_ */
