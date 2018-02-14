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

typedef String UserID;

class UserProfile: public Document {
public:

	bool checkPassword(const StrViewA &password);
	bool checkOTP(unsigned int otpCode);

	void setPassword(const StrViewA &password);
	void enableOTP(const String &secret);
	void disableOTP();

	static Value calculatePasswordDigest(const StrViewA &salt, const StrViewA &password);
};


class UserServices {
public:
	UserServices(CouchDB &db):db(db) {}


	UserID createUser(const String &email);
	UserID findUser(const String &email) const;
	UserProfile loadProfile(const UserID &user);
	void storeProfile(const UserProfile &profile);

protected:
	CouchDB &db;
};

} /* namespace loginsrv */

#endif /* USER_SERVICES_H_ */
