/*
 * user_services.cpp
 *
 *  Created on: Feb 13, 2018
 *      Author: ondra
 */

#include <couchit/query.h>
#include <google_otp/ga.h>
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
				emit(doc._id);
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
				|| expires.getInt() < now) {
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

	Value vemail = email.indexOf("@") != email.npos?Value(email):Value(nullptr);
	Value valias = email.indexOf("@") == email.npos?Value(email):Value(nullptr);


	UserProfile profile ( db.newDocument());
	profile
		   ("tm_created",(std::size_t)now)
		   ("public",Object("state","new")("email", vemail)("alias", valias)("roles",roles));
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

Binary UserProfile::setOTP(StrViewA type) {

	if (isOTPEnabled()) return Binary();

	auto otpsect = object("otp");
	unsigned char bits[10];
	std::random_device rnd;
	std::uniform_int_distribution<unsigned char> dist(0,255);
	for (unsigned int i = 0; i < 10; i++) bits[i] = dist(rnd);
	BinaryView secret(bits,10);
	Value vsecret(secret, base64);
	otpsect.set("secret",vsecret);
	otpsect.unset("counter");
	otpsect.unset("history");
	otpsect.unset("enabled");
	otpsect.set("type",type);
	return vsecret.getBinary(base64);
}

void UserProfile::enableOTP(bool enable) {
	auto otpsect = object("otp");
	otpsect.set("enabled",enable);
}

bool UserProfile::isOTPEnabled() const {
	Value enabled = (*this)["otp"]["enabled"];
	return enabled.getBool();
}

bool UserProfile::checkOTP(unsigned int otpCode) {

	auto otpsect = object("otp");
	auto history = otpsect.array("history");
	for (auto v: history) if (v.getUInt() == otpCode) return false;

	StrViewA type = otpsect["type"].getString();
	if (type == "totp") {
		Binary secret = otpsect["secret"].getBinary(base64);
		GoogleOTP otp(secret);
		if (!otp.checkTimeCode(otpCode,2)) return false;
		history.push_back(otpCode);
		if (history.size() > 4) history.erase(0);
		return true;
	} else if (type == "hotp") {
		Binary secret = otpsect["secret"].getBinary(base64);
		unsigned int counter = otpsect["counter"].getUInt();
		GoogleOTP otp(secret);
		if (!otp.checkCode(counter, otpCode, 10)) return false;
		otpsect.set("counter", counter);
		return true;
	} else {
		return false;
	}
}

unsigned int UserProfile::checkOTPFirstCode(unsigned int code) {
	auto otpsect = object("otp");

	StrViewA type = otpsect["type"].getString();
	if (type == "hotp") {
		Binary secret = otpsect["secret"].getBinary(base64);
		unsigned int counter = otpsect["counter"].getUInt();
		unsigned int zero = 0;
		GoogleOTP otp(secret);
		if (!otp.checkCode(zero, code, 1)) return 0;
		return counter;
	} else {
		return 0;
	}
}

Value UserProfile::getHOTPInfo() const {
	auto otpsect = (*this)["otp"];

	StrViewA type = otpsect["type"].getString();
	if (type == "hotp") {
		Binary secret = otpsect["secret"].getBinary(base64);
		unsigned int counter = otpsect["counter"].getUInt();
		GoogleOTP otp(secret);
		return Object("checkNumber",otp.getCode(0))
					 ("counter", counter);
	} else {
		return nullptr;
	}
}

bool UserProfile::isAdmin() const {
	return hasRole("_admin");
}


bool UserProfile::hasRole(StrViewA role) const {
	Value roles = getRoles();
	for (Value v: roles) if (v.getString() == role) return true;
	return false;
}

Value UserProfile::getRoles() const {
	return operator[]("public")["roles"];
}

Value UserServices::listUsers() const {
	Query lst = db.createQuery(View::includeDocs);
	Result res = lst.range("","_").exec();
	Array out;
	for (Row rw : res) {
		out.push_back({rw.id, rw.doc["public"]["email"], rw.doc["public"]["alias"], rw.doc[CouchDB::fldTimestamp]});
	}
	return out;

}

} /* namespace loginsrv */
