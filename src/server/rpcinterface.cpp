#include <google_otp/base32.h>
#include <sstream>
#include "rpcinterface.h"

#include "shared/vla.h"

using ondra_shared::VLA;

namespace loginsrv {

StrViewA RpcInterface::PURPOSE_REFRESH("refresh");
StrViewA RpcInterface::PURPOSE_CREATE("create");
StrViewA RpcInterface::PURPOSE_ACCOUNT("account");
StrViewA RpcInterface::PURPOSE_ACCOUNT_RO("account_ro");
StrViewA RpcInterface::PURPOSE_ADMIN("_admin");
StrViewA RpcInterface::PURPOSE_ADMIN_RO("_admin_ro");



RpcInterface::RpcInterface(UserServices& us, UserToken& tok, IServices& svc, const Config &cfg)
	:us(us),tok(tok),svc(svc),cfg(cfg),firstUser(false)
{
}


void RpcInterface::registerMethods(RpcServer& srv) {


	srv.add("User.create",this,&RpcInterface::rpcRegisterUser);
	srv.add("User.login",this,&RpcInterface::rpcLogin);
	srv.add("User.setPassword",this,&RpcInterface::rpcSetPassword);
	srv.add("User.resetPassword",this,&RpcInterface::rpcResetPassword);
	srv.add("User.requestResetPassword",this,&RpcInterface::rpcRequestResetPassword);
	srv.add("User.prepareOTP",this,&RpcInterface::rpcUserPrepareOTP);
	srv.add("User.enableOTP",this,&RpcInterface::rpcUserEnableOTP);
	srv.add("User.checkOTP",this,&RpcInterface::rpcUserCheckOTP);
	srv.add("User.verifyOTP",this,&RpcInterface::rpcUserVerifyOTP);
	srv.add("User.loadProfile",this,&RpcInterface::rpcLoadAccount);
	srv.add("User.updateProfile",this,&RpcInterface::rpcSaveAccount);
	srv.add("Token.parse",this,&RpcInterface::rpcTokenParse);
	srv.add("Token.create",this,&RpcInterface::rpcTokenCreate);
	srv.add("Token.revokeAll",this,&RpcInterface::rpcTokenRevokeAll);
	srv.add("Token.getPublicKey",this,&RpcInterface::rpcGetPublicKey);
	srv.add("Admin.loadAccount",this,&RpcInterface::rpcAdminLoadAccount);
	srv.add("Admin.updateAccount",this,&RpcInterface::rpcAdminUpdateAccount);
	srv.add("Admin.listUsers",this,&RpcInterface::rpcAdminListUsers);
	srv.add("Admin.createUser",this,&RpcInterface::rpcAdminCreateUser);
	srv.add("Admin.deleteUser",this,&RpcInterface::rpcAdminDeleteUser);
	srv.add("Admin.logAsUser",this,&RpcInterface::rpcAdminLogAsUser);
	srv.add("Admin.setPassword",this,&RpcInterface::rpcAdminSetPassword);

}

void RpcInterface::rpcRegisterUser(RpcRequest req) {
	static Value argdef = Value::fromString(R"([{"email":"Email", "captcha":["string","undefined"]}])");
	if (!req.checkArgs({argdef})) {
		return req.setArgError();
	}
	auto args = req.getArgs()[0];
	StrViewA email = args["email"].getString();
	StrViewA c = args["captcha"].getString();
	if (!svc.verifyCaptcha(c)) {
		return req.setError(402, "Captcha challenge failed");
	}
	UserID id = us.findUser(email);
	UserProfile prof;
	if (id.empty()) {
		 prof = us.createUser(email);
	} else {
		prof = us.loadProfile(id);
		if (prof["password"].defined()) {
			req.setError(409,"Already exists");
			return;
		}
	}
	String code = prof.genAccessCode("resetpwd", expireAccountCreate);
	us.storeProfile(prof);
	svc.sendMail( email, "register",Object("code", code));
	req.setResult(true);
}

void RpcInterface::rpcTokenRevokeAll(RpcRequest req) {
	if (!req.checkArgs({"string"})) {
		return req.setArgError();
	}
	StrViewA token = req.getArgs()[0].getString();
	UserToken::Info tinfo;
	Value userId = tok.check(token, PURPOSE_CREATE);
	if (!userId.defined()) return sendInvalidToken(req);

	UserProfile prof = us.loadProfile(UserID(tinfo.userId));
	time_t now;time(&now);
	prof("token_revoke", (std::size_t)now);
	us.storeProfile(prof);
	svc.report(prof.getIDValue(), "revokeAllTokens");
	req.setResult(true);
}

void RpcInterface::rpcGetPublicKey(RpcRequest req) {
	req.setResult(tok.getPublicKey());
}

void RpcInterface::rpcResetPassword(RpcRequest req) {
	if (!req.checkArgs({Object("email","Email")("code","Code")("password","Password")})) {
		return req.setArgError();
	}
	auto args = req.getArgs()[0];
	StrViewA email = args["email"].getString();
	StrViewA code= args["code"].getString();
	StrViewA pwd= args["password"].getString();
	UserID id = us.findUser(email);
	if (id.empty()) return sendInvalidToken(req);
	UserProfile prof = us.loadProfile(id);
	auto tr = prof.tryAcccessCode("resetpwd",code);
	auto sendWarn = prof.hasPassword();
	if (tr == UserProfile::accepted) {
		prof.setPassword(pwd);
		req.setResult(true);
		if (sendWarn) svc.sendMail(email,"pwdchanged",Object());
	} else if (tr == UserProfile::invalid) {
			return req.setError(410,"Gone");
	} else {
			sendInvalidToken(req);
	}
	us.storeProfile(prof);
	svc.report(prof.getIDValue(), "lostPwdReset");
}


void RpcInterface::rpcRequestResetPassword(RpcRequest req) {
	static Value argdef = Value::fromString(R"([{"email":"Email", "captcha":["string","optional"]}])");
	if (!req.checkArgs(argdef)) {
		return req.setArgError();
	}
	auto args = req.getArgs()[0];
	StrViewA email = args["email"].getString();
	StrViewA c = args["captcha"].getString();
	if (!svc.verifyCaptcha(c)) {
		return req.setError(402, "Captcha challenge failed");
	}
	UserID id = us.findUser(email);
	if (id.empty()) return req.setError(404,"Not found");
	UserProfile prof = us.loadProfile(id);
	String code = prof.genAccessCode("resetpwd", expireAccountCreate);
	us.storeProfile(prof);
	svc.sendMail(email,"resetpwd",Object("code", code));

	req.setResult(true);
	svc.report(prof.getIDValue(), "lostPwdResetReq");

}

void RpcInterface::rpcGetAccountName(RpcRequest req) {
	if (!req.checkArgs({"string"})) {
		return req.setArgError();
	}
	auto args = req.getArgs();
	StrViewA token = args[0].getString();
	UserToken::Info tinfo;
	if (tok.parse(token,tinfo) == UserToken::invalid) return sendInvalidToken(req);
	UserProfile prof = us.loadProfile(tinfo.userId);
	req.setResult(Object("email", prof["email"])
						("state", prof["state"]));


}

void RpcInterface::rpcLoadAccount(RpcRequest req) {
	if (!req.checkArgs({"Token"})) {
		return req.setArgError();
	}
	auto args = req.getArgs();
	StrViewA token = args[0].getString();
	Value userId = tok.check(token, { PURPOSE_ACCOUNT, PURPOSE_ACCOUNT_RO });
	if (!userId.defined()) return sendInvalidToken(req);
	UserProfile prof = us.loadProfile(userId);
	req.setResult(prof["public"]);
}

void RpcInterface::rpcSaveAccount(RpcRequest req) {
	if (!req.checkArgs({"Token", Object("%","any")})) {
		return req.setArgError();
	}
	auto args = req.getArgs();
	StrViewA token = args[0].getString();
	Value update = args[1];
	Value userId = tok.check(token, PURPOSE_ACCOUNT);
	if (!userId.defined()) return sendInvalidToken(req);
	UserProfile p = us.loadProfile(userId);
	if (update["roles"].defined() || update["email"].defined()) {
		return req.setError(403,"Forbidden","Can't update read-only fields");
	}
	if (update["alias"].defined()) {
		StrViewA a = update["alias"].getString();
		if (!a.empty()) {
			UserID id = us.findUser(a);
			if (!id.empty() && id != String(userId))
				return req.setError(409,"Alias is already used");
		}
	}
	p = Value(p).merge(Object("public",update));
	us.storeProfile(p);
	req.setResult(Value(p)["public"]);
	svc.report(p.getIDValue(), "accountUpdate", update);

}

void RpcInterface::rpcUserPrepareOTP(RpcRequest req) {
	static Value argdef = Value::fromString(R"(["Token",["'totp","'hotp"]])");
	if (!req.checkArgs(argdef)) return req.setArgError();
	StrViewA token = req.getArgs()[0].getString();
	Value userId = tok.check(token, PURPOSE_ACCOUNT);
	if (!userId.defined()) return sendInvalidToken(req);

	StrViewA type = req.getArgs()[1].getString();
	UserProfile prof = us.loadProfile(userId);
	BinaryView bin = prof.setOTP(type);
	us.storeProfile(prof);

	VLA<char, 100> secret((bin.length*8+4)/5);
	base32_encode(bin.data, bin.length, reinterpret_cast<uint8_t *>(secret.data), secret.length);

	std::ostringstream urlbuff;
	urlbuff << "otpauth://" << type << "/" << svc.getOTPLabel(prof) << "?secret=" << StrViewA(secret);
	if (type=="hotp") urlbuff << "&counter=0";
	req.setResult(urlbuff.str());
	svc.report(prof.getIDValue(), "prepareOTP", type);


}

void RpcInterface::rpcUserEnableOTP(RpcRequest req) {
	static Value argdef = Value::fromString(R"(["Token","number","boolean"])");
	if (!req.checkArgs(argdef)) return req.setArgError();

	StrViewA token = req.getArgs()[0].getString();
	std::size_t code = req.getArgs()[1].getUInt();
	bool enable  = req.getArgs()[2].getBool();
	UserToken::Info tinfo;
	if (tok.parse(token,tinfo)) return sendInvalidToken(req);

	UserProfile prof = us.loadProfile(tinfo.userId);
	if (prof.isOTPEnabled() == enable) return req.setResult(true);

	if (!prof.checkOTP(code)) return req.setError(401,"Invalid OTP code");

	prof.enableOTP(enable);

	us.storeProfile(prof);
	req.setResult(true);
	svc.report(prof.getIDValue(), "enableOTP", enable);

}


void RpcInterface::sendInvalidToken(RpcRequest req) {
	return req.setError(402, "Invalid token");
}

void RpcInterface::rpcTokenParse(RpcRequest req) {
	if (!req.checkArgs({"Token"})) {
		return req.setArgError();
	}
	StrViewA token = req.getArgs()[0].getString();
	UserToken::Info tinfo;
	UserToken::Status st = tok.parse(token,tinfo);

	Object result;

	result("user", tinfo.userId)
		  ("created", tinfo.created)
		  ("expires", tinfo.expireTime)
		  ("purpose", tinfo.purpose)
		  ("roles", tinfo.roles)
		  ("raw", tok.parseToken(token).toString());

	switch (st) {
	case UserToken::expired:
		result("status","expired");
		break;
	case UserToken::valid:
		result("status","valid");
		break;
	case UserToken::invalid:
		return sendInvalidToken(req);
	}
	req.setResult(result);
}


void RpcInterface::rpcTokenCreate(RpcRequest req) {
	static Value argDef = Value::fromString(R"json(
		["Token",[[1],"Purpose","Purpose"], ["number","undefined"]]
     )json");

	if (!req.checkArgs(argDef)) return req.setArgError();
	auto args = req.getArgs();
	StrViewA token = args[0].getString();
	UserToken::Info nfo;
	if (tok.parse(token,nfo)) return sendInvalidToken(req);
	Value limits;
	static Value rootVal(PURPOSE_CREATE);
	static Value refreshVal(PURPOSE_REFRESH);
	bool isRefresh;
	if (nfo.purpose == refreshVal || (nfo.purpose.size() == 2 && nfo.purpose[0] == refreshVal)) {
		limits = nfo.purpose[1];
		isRefresh = true;
	}
	else if (nfo.purpose == rootVal || nfo.purpose.indexOf(rootVal) != nfo.purpose.npos) {
		isRefresh = false;
	} else {
		return req.setError(403,"Forbidden","The Token hasn't the ability to create other tokens");
	}

	UserProfile prof(us.loadProfile(nfo.userId));
	time_t revoke_time = prof["token_revoke"].getUInt();
	if (nfo.created < revoke_time) {
		return req.setError(410,"Token revoked");
	}

	Value purposes = args[1];
	unsigned int maxExpiration = args[2].getUInt();
	if (maxExpiration == 0) maxExpiration = std::max(cfg.refreshTokenExpiration_sec,cfg.rootTokenExpiration_sec);
	unsigned int rfrexp = std::min(maxExpiration, cfg.refreshTokenExpiration_sec);
	unsigned int rootexp = std::min(maxExpiration, cfg.rootTokenExpiration_sec);
	Array res;
	for (Value v : purposes) {
		Value roles;
		unsigned int me = rootexp;
		Value finalRoles;
		if (v.type() == json::string) {
			if (v == refreshVal) {
				if (isRefresh) finalRoles = nfo.purpose;
				else return req.setError(403,"Forbidden","The token hasn't the ability to create refresh tokens");
				me = rfrexp;
			} else {
				if (limits.defined() && limits.indexOf(v) == limits.npos) return req.setError(403,"Forbidden","Limited");
				finalRoles = v;
				roles = prof.getRoles();
			}

		} else if (v.type() == json::array && !v.empty()) {
			if (v[0] == refreshVal) {
				if (v.size() != 2 || v[1].type() != json::array || v[1].empty())
					return req.setError(400,"Bad request","Invalid purpose for the refresh token");
				if (isRefresh) {
					if (limits.defined()) {
						Value filtered = v[1].sort(&Value::compare).intersection(limits.sort(&Value::compare));
						if (filtered.empty()) {
							return req.setError(403,"Forbidden","Limited");
						}
						finalRoles = {v[0],filtered};
					} else {
						finalRoles = v;
					}
					me = rfrexp;
				} else {
					return req.setError(403,"Forbidden","The token hasn't the ability to create refresh tokens");
				}
			} else {
				if (limits.defined()) {
					finalRoles = v.sort(&Value::compare).intersection(limits.sort(&Value::compare));
					if (finalRoles.empty()) return req.setError(403,"Forbidden","Limited");
				} else {
					finalRoles = v;
				}
				roles = prof.getRoles();
			}
		} else {
			return req.setError(400,"Bad request","Invalid purpose for the token");
		}

		if (finalRoles.indexOf(refreshVal,1) != finalRoles.npos) {
			return req.setError(400,"Bad request","Purpose refresh cannot be used in list of purposes");
		}
		UserToken::Info newinfo = tok.prepare(nfo.userId,finalRoles, roles,me);
		res.push_back(outTokenInfo(newinfo));
	}
	req.setResult(res);

}

void RpcInterface::sendUserLocked(RpcRequest& req) {
	return req.setError(423, "User is locked",
			Object("wait_sec", cfg.userLockWait));
}

Value RpcInterface::outTokenInfo(const UserToken::Info &info) {
	return Value(json::object,{
		Value("expires",info.expireTime),
		Value("token",tok.create(info))
	});



}

void RpcInterface::rpcLogin(RpcRequest req) {
	static Value argDef = Value::fromString(
			R"([{"user":"string","password":"string",
"otp":["number","undefined"],"purpose":[[[],"Purpose"],"undefined"]}])");

	static Value normalPurposes(json::array, {
			{ PURPOSE_CREATE, PURPOSE_ACCOUNT } });

	if (!req.checkArgs(argDef)) {
		return req.setArgError();
	}
	Value args = req.getArgs()[0];
	Value user = args["user"];
	StrViewA password = args["password"].getString();
	unsigned int otp = args["otp"].getUInt();
	Value purpose = args["purpose"];
	if (!purpose.defined()) purpose = {normalPurposes};

	time_t now;
	time(&now);
	time_t locktime = now + cfg.userLockWait;

	UserID userid = us.findUser(user.getString());
	if (userid.empty()) {
		if (ulock.isUserLocked(user) > now) {
			return sendUserLocked(req);
		}
		req.setError(401,"Invalid credentials");
		//perform maintenance
		ulock.unlockUser(nullptr,now);
		//lock
		ulock.lockUser(user, locktime);
		return;
	}



	//if user is locked, do not continue in login
	if (ulock.isUserLocked(user) > now) {
		return sendUserLocked(req);
	}

	UserProfile prof = us.loadProfile(userid);
	if (prof.checkPassword(password)) {



		if (prof.isOTPEnabled()) {
			if (otp) {
				if (!prof.checkOTP(otp)) {
					Value data;
					unsigned int cnt = prof.checkOTPFirstCode(otp);
					if (cnt) data = Object("counter",cnt);
					//lock when invalid OTP to prevent brutalforcing OTP
					ulock.lockUser(user, locktime);
					svc.report(prof.getIDValue(), "loginFailOTP");
					return req.setError(401,"Invalid credentials",data);
				} else {
					us.storeProfile(prof);
				}
			} else {
				svc.report(prof.getIDValue(), "loginFailNoOTP");
				return req.setError(402,"OTP Required");
			}
		}

		String choosenConfig (prof["config"]);
		Value ucfg = svc.getUserConfig(choosenConfig);
		Object res;
		res("config", ucfg);
		Array tokens;
		for (Value p: purpose) {
			std::size_t expire;
			if (p.getString() == PURPOSE_REFRESH
					|| p[0].getString() == PURPOSE_REFRESH) {
				expire = cfg.refreshTokenExpiration_sec;
			} else {
				expire = cfg.rootTokenExpiration_sec;
			}
			UserToken::Info tnfo = tok.prepare(userid,p,prof.getRoles(), expire);
			tokens.push_back(outTokenInfo(tnfo));

		}
		res("tokens",tokens);

		//unlock user now (and perform maintenance)
		ulock.unlockUser(user, now);
		req.setResult(res);
		svc.report(prof.getIDValue(), "loginSuccess");
	} else {
		//lock user
		ulock.lockUser(user, locktime);
		req.setError(401,"Invalid credentials");
		svc.report(prof.getIDValue(), "loginFailPwd");

	}
}

void RpcInterface::rpcSetPassword(RpcRequest req) {
	if (!req.checkArgs({"Token","string","string"})) {
		return req.setArgError();
	}
	Value args = req.getArgs();
	StrViewA token = args[0].getString();
	StrViewA old_password = args[1].getString();
	StrViewA password = args[2].getString();
	Value userId = tok.check(token, PURPOSE_ACCOUNT);
	if (!userId.defined()) return sendInvalidToken(req);

	UserProfile prof = us.loadProfile(UserID(userId));
	if (!prof.checkPassword(old_password)) {
		req.setError(403,"Password doesn't match");
		svc.report(prof.getIDValue(), "setPwdFailed");
	} else {
		prof.setPassword(password);
		us.storeProfile(prof);
		svc.sendMail(prof["public"]["email"].getString(),"pwdchanged",Object());
		req.setResult(true);
		svc.report(prof.getIDValue(), "setPwdOk");
	}
}

void RpcInterface::rpcAdminLoadAccount(RpcRequest req) {
	if (!req.checkArgs({"Token","string"})) {
		return req.setArgError();
	}
	auto args = req.getArgs();
	StrViewA token = args[0].getString();
	StrViewA victim = args[1].getString();
	Value userId = tok.check(token,{PURPOSE_ADMIN,PURPOSE_ACCOUNT_RO},"_admin");
	if (!userId.defined()) return sendInvalidToken(req);

	UserID uid = us.findUser(victim);
	if (uid.empty()) return req.setError(404,"Not found");
	UserProfile prof = us.loadProfile(uid);
	req.setResult(Value(prof).replace("_id",json::undefined).replace("_rev",json::undefined));
	svc.report(userId, "adminLoadAccount", uid);
}

void RpcInterface::rpcAdminUpdateAccount(RpcRequest req) {
	static Value argdef = Value::fromString(
	R"json(["Token","string",{
			"_id":"undefined",
			"_rev":"undefined",
			"%":"any"		
	}])json");
	if (!req.checkArgs(argdef)) return req.setArgError();

	auto args = req.getArgs();
	StrViewA token = args[0].getString();
	StrViewA victim = args[1].getString();
	Value update = args[2];
	Value userId = tok.check(token,PURPOSE_ADMIN,"_admin");
	if (!userId.defined()) return sendInvalidToken(req);

	UserID uid = us.findUser(victim);
	UserProfile prof = us.loadProfile(uid);
	prof = Value(prof).merge(update);
	us.storeProfile(prof);
	req.setResult(Value(prof).replace("_id",json::undefined).replace("_rev",json::undefined));
	svc.report(prof.getIDValue(), "accountUpdateAdmin", {userId, update});
}

void RpcInterface::rpcUserCheckOTP(RpcRequest req) {

	if (!req.checkArgs({"Token","number"})) return req.setArgError();
	auto args = req.getArgs();
	StrViewA token = args[0].getString();
	unsigned int code = args[1].getUInt();
	UserToken::Info tinfo;
	if (tok.parse(token,tinfo)) return sendInvalidToken(req);
	UserProfile prof = us.loadProfile(UserID(tinfo.userId));
	if (prof.checkOTP(code)) {
		us.storeProfile(prof);
		req.setResult(true);
	} else {
		req.setResult(false);
	}

}

void RpcInterface::rpcUserVerifyOTP(RpcRequest req) {
	if (!req.checkArgs(Value(json::array,{"Token"}))) return req.setArgError();
	auto args = req.getArgs();
	StrViewA token = args[0].getString();
	Value userId = tok.check(token, PURPOSE_CREATE);
	if (!userId.defined()) return sendInvalidToken(req);
	UserProfile prof = us.loadProfile(UserID(userId));
	Value nfo = prof.getHOTPInfo();
	if (nfo.isNull()) req.setError(404,"No HTOP informations are available");
	else req.setResult(nfo);
}

void RpcInterface::rpcAdminListUsers(RpcRequest req) {
	if (!req.checkArgs({"Token"})) return req.setArgError();
	auto args = req.getArgs();
	StrViewA token = args[0].getString();
	Value userId = tok.check(token,{PURPOSE_ADMIN,PURPOSE_ADMIN_RO},"_admin");
	if (!userId.defined()) return sendInvalidToken(req);

	req.setResult(us.listUsers());
}

void RpcInterface::rpcAdminCreateUser(RpcRequest req) {
	if (!req.checkArgs({"Token","string"})) return req.setArgError();
	auto args = req.getArgs();
	StrViewA token = args[0].getString();
	StrViewA newid = args[1].getString();
	Value userId = tok.check(token,PURPOSE_ADMIN,"_admin");
	if (!userId.defined()) return sendInvalidToken(req);
	UserID u = us.findUser(newid);
	if (u.empty()) {
		UserProfile p = us.createUser(newid);
		us.storeProfile(p);
		svc.report(userId, "adminCreateUser", u);
		return rpcAdminLoadAccount(req);
	} else {
		return req.setError(409,"Already exists");
	}
}

void RpcInterface::rpcAdminDeleteUser(RpcRequest req) {
	if (!req.checkArgs({"Token","string"})) return req.setArgError();
	auto args = req.getArgs();
	StrViewA token = args[0].getString();
	StrViewA newid = args[1].getString();
	Value userId = tok.check(token,PURPOSE_ADMIN,"_admin");
	if (!userId.defined()) return sendInvalidToken(req);
	UserID u = us.findUser(newid);
	if (u.empty()) return req.setError(404,"Not found");
	UserProfile prof = us.loadProfile(u);
	prof.set("_deleted",true);
	us.storeProfile(prof);
	req.setResult(true);
	svc.report(userId, "adminDeleteUser", u);
}

void RpcInterface::rpcAdminLogAsUser(RpcRequest req) {
	if (!req.checkArgs({"Token","string"})) return req.setArgError();
	auto args = req.getArgs();
	StrViewA token = args[0].getString();
	StrViewA victim = args[1].getString();
	Value userId = tok.check(token,PURPOSE_ADMIN,"_admin");
	if (!userId.defined()) return sendInvalidToken(req);
	UserID u = us.findUser(victim);
	if (u.empty()) return req.setError(404,"Not found");
	UserProfile prof = us.loadProfile(u);

	auto inf = tok.prepare(u, { PURPOSE_CREATE, PURPOSE_ACCOUNT },
			prof.getRoles(),
			cfg.rootTokenExpiration_sec);
	String choosenConfig (prof["config"]);
	Value ucfg = svc.getUserConfig(choosenConfig);

	Object res;
	res("token", tok.create(inf))
	   ("expires", inf.expireTime)
	   ("config", ucfg);

	req.setResult(res);
	svc.report(userId, "adminLoginAsUser", u);


}

void RpcInterface::rpcAdminSetPassword(RpcRequest req) {
	if (!req.checkArgs({"Token","string","Password"})) return req.setArgError();
	auto args = req.getArgs();
	StrViewA token = args[0].getString();
	StrViewA id = args[1].getString();
	StrViewA password = args[2].getString();
	Value userId = tok.check(token,PURPOSE_ADMIN,"_admin");
	if (!userId.defined()) return sendInvalidToken(req);
	UserID u = us.findUser(id);
	if (u.empty()) return req.setError(404,"Not found");
	UserProfile prof = us.loadProfile(u);
	prof.setPassword(password);
	us.storeProfile(prof);
	req.setResult(true);
	svc.report(prof.getIDValue(), "setPwdOkAdmin");
}


}

