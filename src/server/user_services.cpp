/*
 * user_services.cpp
 *
 *  Created on: Feb 13, 2018
 *      Author: ondra
 */

#include <server/user_services.h>
#include <openssl/hmac.h>
#include <random>

namespace loginsrv {

static const int saltLen = 16;

String generateSalt() {
	return String(saltLen,[](char *c){
		std::random_device rnd;
		std::uniform_int_distribution<> dist('0','~');
		for (int i = 0; i < saltLen; i++) c[i] = dist(rnd);
		return saltLen;
	});

}

Value UserProfile::calculatePasswordDigest(const StrViewA &salt, const StrViewA &password) {
	BinaryView bsalt(salt);
	BinaryView bpswd(password);

	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int digestLen = EVP_MAX_MD_SIZE;
	if (HMAC(EVP_sha256(),
			bpswd.data, bpswd.length,
			bsalt.data, bsalt.length,
			digest,&digestLen) == nullptr) {
		throw std::runtime_error("Failed to calculate password hash");
	}

	return Value(BinaryView(digest, digestLen),base64url);
}



void UserProfile::setPassword(const StrViewA& password) {
	String salt = generateSalt();
	object("password")
		("salt", salt);
		("digest", calculatePasswordDigest(salt, password));
}


bool UserProfile::checkPassword(const StrViewA& password) {
	Value pwsc = (*this)["password"];
	if (pwsc.defined()) {

		String salt(pwsc["salt"]);
		Binary digest(pwsc["digest"].getBinary(base64url));
		Binary calcDigest = calculatePasswordDigest(salt, password).getBinary(base64url);
		return calcDigest == digest;

	} else {
		return false;
	}

}

bool UserProfile::checkOTP(unsigned int otpCode) {
}


void UserProfile::enableOTP(const String& secret) {
}

void UserProfile::disableOTP() {
}

UserID UserServices::createUser(const StrViewA& email) {
	String userTag({"user:",email});
	UserID userId ( db.genUID());
	Document userReg;
	userReg.setID(userTag);
	userReg.set("profile", userId);
	db.put(userReg);

	time_t now;
	time(&now);


	UserProfile profile;
	profile.setID(userId);
	profile("email", email)
		   ("createTime",(std::size_t)now)
		   ("state","new");
	db.put(profile);
	return userId;
}

UserID UserServices::findUser(const StrViewA& email) const {
	String userTag({"user:",email});
	Value doc = db.get(userTag,CouchDB::flgNullIfMissing);
	return UserID(doc["profile"]);
}

UserProfile UserServices::loadProfile(const UserID& user) {
	return UserProfile(db.get(user));
}

void UserServices::storeProfile( UserProfile& profile) {
	db.put(profile);
}

} /* namespace loginsrv */
