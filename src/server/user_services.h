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

	using Document::Document;

	bool checkPassword(const StrViewA &password);
	bool checkOTP(unsigned int otpCode);

	void setPassword(const StrViewA &password);
	void enableOTP(const String &secret);
	void disableOTP();
	void activate();

	static Value calculatePasswordDigest(const StrViewA &salt, const StrViewA &password);
};


class UserServices {
public:
	UserServices(CouchDB &db):db(db) {}


	UserID createUser(const StrViewA &email);
	UserID findUser(const StrViewA &email) const;
	UserProfile loadProfile(const UserID &user);
	void storeProfile(UserProfile &profile);

protected:
	CouchDB &db;
};

} /* namespace loginsrv */

#endif /* USER_SERVICES_H_ */
