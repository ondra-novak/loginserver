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

UserServices::UserServices(CouchDB &db):db(db) {
	CouchDB::fldTimestamp = "tm_modified";
}

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
	Value digest = calculatePasswordDigest(salt, password);
	object("password")
		("salt", salt)
		("digest", digest);
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
return false;
}


void UserProfile::enableOTP(const String& secret) {
}

void UserProfile::disableOTP() {
}

String UserProfile::genAccessCode(String purpose, std::size_t expire_tm) {

	std::random_device rnd;
	std::uniform_int_distribution<> dist('0','9');

	char code[accessCodeLen];
	for (int i = 0; i < accessCodeLen; i++) {
		if (i % accessCodeSep == accessCodeSep-1) code[i] = '-';
		else code[i] = dist(rnd);
	}

	time_t now;
	time(&now);

	object("access_code")
		("code", StrViewA(code, accessCodeLen))
		("purpose", purpose)
		("tries", accessCodeTries)
		("expires", now+expire_tm);
	return StrViewA(code, accessCodeLen);

}
UserProfile::TryResult UserProfile::tryAcccessCode(String purpose, String code) {
	bool clear = false;
	TryResult tr;
	{
		auto sec = object("access_code");
		ValueRef curcode(sec,"code");
		ValueRef curpurpose(sec,"purpose");
		ValueRef expires(sec,"expires");
		ValueRef tries(sec,"tries");

		time_t now;
		time(&now);

		if (curpurpose != purpose
				|| !curcode.defined()
				|| !expires.defined()
				|| expires.getUInt() < now) {
			tr = invalid;
		} else if (curcode.getString() != code) {

			int newtries = tries.getUInt()-1;
			if (newtries == 0) {
				clear = true;
			} else {
				tries = newtries;
			}
			tr = rejected;
		} else {
			clear = true;
			tr = accepted;
		}
	}
	if (clear) unset("access_code");
	return tr;
}



UserProfile UserServices::createUser(const StrViewA& email) {
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
	profile
		   ("tm_created",(std::size_t)now)
		   ("public",Object("state","new")("email", email));
	profile.enableTimestamp();
	return profile;
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

