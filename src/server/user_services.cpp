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

UserID UserServices::createUser(const String& email) {
	Value id = db.genUID();
	Document usersrch;
	usersrch.setID(String({"user:",email}));
	usersrch.set("profile", id);

}

UserID UserServices::findUser(const String& email) const {
}

UserProfile UserServices::loadProfile(const UserID& user) {
}

void UserServices::storeProfile(const UserProfile& profile) {
}

} /* namespace loginsrv */
