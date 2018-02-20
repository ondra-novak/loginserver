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

	void setPassword(const StrViewA &password);
	///Sets OTP
	/**
	 * Sets new OTP params. If there is an active OTP, function fails
	 *
	 * @param type either "totp" or "hotp"
	 * @return secret in binary form. Function returns an empty view in case of failure
	 */
	Binary setOTP(StrViewA type);
	///Enables or disables OTP
	/**
	 * Function just manipulates with isOTPEnabled. Event if OTP is disabled, checkOTP
	 * is still works
	 *
	 */
	void enableOTP(bool enable);
	///Determines whether OTP is enabled
	bool isOTPEnabled() const;
	///Checks OTP code
	/**
	 *
	 * @param code code to check
	 * @retval false failure
	 * @retval true succes (match). The profile MUST be saved after successuly check
	 */
	bool checkOTP(unsigned int code);

	///checks for the first code
	/**
	 * @param code code
	 * @retval 0 invalid code
	 * @retval >0 current counter value (to help with recorvery)
	 */
	unsigned int checkOTPFirstCode(unsigned int code);

	Value getHOTPInfo() const;

	bool hasPassword() const;

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
	bool nextUserIsAdmin;
};

class UserAlreadyExists: public std::exception {
public:
	const char *what() const noexcept(true) {return "user already exists";};
};

} /* namespace loginsrv */

#endif /* USER_SERVICES_H_ */
