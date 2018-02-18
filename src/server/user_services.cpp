/*
 * user_services.cpp
 *
 *  Created on: Feb 13, 2018
 *      Author: ondra
 */

#include <couchit/query.h>
#include <server/user_services.h>
#include <openssl/hmac.h>
#include <random>

namespace loginsrv {

static const int saltLen = 16;


StrViewA findUserDesignDoc = R"json({
	"_id":"_design/users",
	"language":"javascript",
	"views":{
		"find_login":{
			"map":function(doc) {
				if (doc.public.email) emit(doc.public.email, null);
				if (doc.public.alias) emit(doc.public.alias, null);
			}
		}
	}
})json";
View findUserView("_design/users/_view/find_login", View::update);

UserServices::UserServices(CouchDB &db):db(db) {
	CouchDB::fldTimestamp = "tm_modified";

	db.putDesignDocument(findUserDesignDoc.data,findUserDesignDoc.length);
	nextUserIsAdmin = Result(db.createQuery(findUserView).limit(0).exec()).getTotal() == 0;
}

String generateSalt() {
	return String(saltLen,[](char *c){
		std::random_device rnd;
		std::uniform_int_distribution<> dist('0','~');
		for (int i = 0; i < saltLen; i++) c[i] = dist(rnd);
		return saltLen;
	});

}

bool UserProfile::hasPassword() const {
	return this->operator []("password").defined();
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
	UserID user = findUser(email);
	if (!user.empty()) throw UserAlreadyExists();

	time_t now;
	time(&now);

	Value roles;
	if (nextUserIsAdmin) roles = Value(json::array, {"_admin"});
	else roles = json::array;
	nextUserIsAdmin = false;

	UserProfile profile ( db.newDocument());
	profile
		   ("tm_created",(std::size_t)now)
		   ("public",Object("state","new")("email", email)("alias", nullptr)("roles",roles));
	profile.enableTimestamp();
	return profile;
}

UserID UserServices::findUser(const StrViewA& email) const {
	Query q = db.createQuery(findUserView);
	Result res = q.key(email).exec();
	if (res.empty()) return String();
	else return Row(res[0]).id;
}

UserProfile UserServices::loadProfile(const UserID& user) {
	return UserProfile(db.get(user));
}

void UserServices::storeProfile( UserProfile& profile) {
	db.put(profile);
}



} /* namespace loginsrv */

