#include <google_otp/base32.h>
#include <sstream>
#include "rpcinterface.h"

#include "shared/vla.h"

using ondra_shared::VLA;

namespace loginsrv {



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
	if (tok.parse(token,tinfo))
		return sendInvalidToken(req);

	UserProfile prof = us.loadProfile(UserID(tinfo.userId));
	time_t now;time(&now);
	prof("tokenRevoke", (std::size_t)now);
	us.storeProfile(prof);
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
	UserToken::Info tinfo;
	if (tok.parse(token,tinfo) != UserToken::valid) return sendInvalidToken(req);
	UserProfile prof = us.loadProfile(tinfo.userId);
	req.setResult(prof["public"]);
}

void RpcInterface::rpcSaveAccount(RpcRequest req) {
	if (!req.checkArgs({"Token", Object("%","any")})) {
		return req.setArgError();
	}
	auto args = req.getArgs();
	StrViewA token = args[0].getString();
	Value update = args[1];
	UserToken::Info tinfo;
	if (tok.parse(token,tinfo) != UserToken::valid) return sendInvalidToken(req);
	UserProfile p = us.loadProfile(tinfo.userId);
	if (update["roles"].defined() || update["email"].defined()) {
		return req.setError(403,"Forbidden","Can't update read-only fields");
	}
	if (update["alias"].defined()) {
		StrViewA a = update["alias"].getString();
		if (!a.empty()) {
			UserID id = us.findUser(a);
			if (!id.empty() && id != String(tinfo.userId))
				return req.setError(409,"Alias is already used");
		}
	}
	p = Value(p).merge(Object("public",update));
	us.storeProfile(p);
	req.setResult(Value(p)["public"]);
}

void RpcInterface::rpcUserPrepareOTP(RpcRequest req) {
	static Value argdef = Value::fromString(R"(["Token",["'totp","'hotp"]])");
	if (!req.checkArgs(argdef)) return req.setArgError();
	StrViewA token = req.getArgs()[0].getString();
	UserToken::Info tinfo;
	if (tok.parse(token,tinfo)) return sendInvalidToken(req);

	StrViewA type = req.getArgs()[1].getString();
	UserProfile prof = us.loadProfile(tinfo.userId);
	BinaryView bin = prof.setOTP(type);
	us.storeProfile(prof);

	VLA<char, 100> secret((bin.length*8+4)/5);
	base32_encode(bin.data, bin.length, reinterpret_cast<uint8_t *>(secret.data), secret.length);

	std::ostringstream urlbuff;
	urlbuff << "otpauth://" << type << "/" << svc.getOTPLabel(prof) << "?secret=" << StrViewA(secret);
	if (type=="hotp") urlbuff << "&counter=0";
	req.setResult(urlbuff.str());

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

	switch (st) {
	case UserToken::expired:
		if (!req.getContext()["inspect"].getBool()) {
			return req.setError(410,"Token expired");
		} else {
			result("status","expired");
		}//nobreak
	case UserToken::valid:
		result("user", tinfo.userId)
			  ("created", tinfo.created)
			  ("expires", tinfo.expireTime)
			  ("purpose", tinfo.purpose);
		break;
	case UserToken::invalid:
		return sendInvalidToken(req);
	}
	req.setResult(result);
}


void loginsrv::RpcInterface::rpcTokenCreate(RpcRequest req) {
	static Value argDef = Value::fromString(R"json(
		["Token",[[1],"Purpose","Purpose"], ["number","undefined"]
     )json");

	if (!req.checkArgs(argDef)) return req.setArgError();
	auto args = req.getArgs();
	StrViewA token = args[0].getString();
	UserToken::Info nfo;
	if (tok.parse(token,nfo)) return sendInvalidToken(req);
	bool isRefresh = nfo.purpose == "refresh";
	if (nfo.purpose != "root" && !isRefresh) return req.setError(403,"Forbidden","The Token hasn't ability to create other tokens");
	Value purposes = args[1];
	unsigned int maxExpiration = args[2].getUInt()-1;
	unsigned int rfrexp = std::min(maxExpiration, cfg.refreshTokenExpiration_sec);
	unsigned int rootexp = std::min(maxExpiration, cfg.rootTokenExpiration_sec);
	Object res;
	for (Value v : purposes) {
		unsigned int me = rootexp;
		if (v.getString() == "refresh") {
			if (isRefresh) {
				me = rfrexp;
			} else {
				return req.setError(403,"Forbidden","The Token is not refresh");
			}
		}
		UserToken::Info newinfo = tok.prepare(nfo.userId,String(v), me);
		res(v.getString(), tok.create(newinfo));
	}
	req.setResult(res);

}


void RpcInterface::rpcLogin(RpcRequest req) {
	static Value argDef = Value::fromString(
	 "[{\"user\":\"string\","
	 "\"password\":\"Password\","
	 "\"otp\":[\"number\",\"optional\"],"
	 "\"keep\":[\"boolean\",\"optional\"]}]");

	if (!req.checkArgs(argDef)) {
		return req.setArgError();
	}
	Value args = req.getArgs()[0];
	StrViewA user = args["user"].getString();
	StrViewA password = args["password"].getString();
	unsigned int otp = args["otp"].getUInt();
	bool remember = args["keep"].getBool();

	try {
		UserID userid = us.findUser(user);
		UserProfile prof = us.loadProfile(userid);
		if (prof.checkPassword(password)) {

			if (prof.isOTPEnabled()) {
				if (otp) {
					if (!prof.checkOTP(otp)) {
						Value data;
						unsigned int cnt = prof.checkOTPFirstCode(otp);
						if (cnt) data = Object("counter",cnt);
						req.setError(401,"Invalid credentials",data);
					} else {
						us.storeProfile(prof);
					}
				} else {
					req.setError(402,"OTP Required");
				}
			}
			UserToken::Info tnfo = tok.prepare(userid, "root", cfg.rootTokenExpiration_sec);
			String token = tok.create(tnfo);
			String choosenConfig (prof["config"]);
			Value ucfg = svc.getUserConfig(choosenConfig);

			Object res;
			res("token", token)
			   ("expires", tnfo.expireTime)
			   ("config", ucfg);

			if (remember) {
				tnfo = tok.prepare(userid,"refresh", cfg.refreshTokenExpiration_sec);
				res("refresh",tok.create(tnfo));
			}

			req.setResult(res);
		} else {
			req.setError(401,"Invalid credentials");
		}
	} catch (...) {
		req.setError(401,"Invalid credentials");
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
	UserToken::Info tinfo;
	if (tok.parse(token,tinfo)) return sendInvalidToken(req);

	UserProfile prof = us.loadProfile(UserID(tinfo.userId));
	if (!prof.checkPassword(old_password)) {
		req.setError(403,"Password doesn't match");
	} else {
		prof.setPassword(password);
		us.storeProfile(prof);
		svc.sendMail(prof["public"]["email"].getString(),"pwdchanged",Object());
		req.setResult(true);
	}
}

void RpcInterface::rpcAdminLoadAccount(RpcRequest req) {
	if (!req.checkArgs({"Token","string"})) {
		return req.setArgError();
	}
	auto args = req.getArgs();
	StrViewA token = args[0].getString();
	StrViewA userid = args[1].getString();
	UserToken::Info tinfo;
	if (tok.parse(token,tinfo) != UserToken::valid) return sendInvalidToken(req);
	UserProfile prof = us.loadProfile(tinfo.userId);
	if (Value(prof)["public"]["roles"].indexOf("_admin") == Value::npos)
		return req.setError(403,"Forbidden");
	UserID uid = us.findUser(userid);
	if (uid.empty()) return req.setError(404,"Not found");
	prof = us.loadProfile(uid);
	req.setResult(Value(prof).replace("_id",json::undefined).replace("_rev",json::undefined));
}

void RpcInterface::rpcAdminUpdateAccount(RpcRequest req) {
	static Value argdef = Value::fromString(
	R"json(["string","Token",{
			"_id":"undefined",
			"_rev":"undefined",
			"%":"any		
	})json");
	if (!req.checkArgs(argdef)) return req.setArgError();

	auto args = req.getArgs();
	StrViewA token = args[0].getString();
	StrViewA userid = args[1].getString();
	Value update = args[2];
	UserToken::Info tinfo;
	if (tok.parse(token,tinfo) != UserToken::valid) return sendInvalidToken(req);
	UserProfile prof = us.loadProfile(tinfo.userId);
	if (Value(prof)["public"]["roles"].indexOf("_admin") == Value::npos)
		return req.setError(403,"Forbidden");
	UserID uid = us.findUser(userid);
	if (uid.empty()) return req.setError(404,"Not found");
	prof = us.loadProfile(uid);
	prof = Value(prof).merge(Object("public",update));
	us.storeProfile(prof);
	req.setResult(Value(prof)["public"]);
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

void loginsrv::RpcInterface::rpcUserVerifyOTP(RpcRequest req) {
	if (!req.checkArgs(Value(json::array,{"Token"}))) return req.setArgError();
	auto args = req.getArgs();
	StrViewA token = args[0].getString();
	UserToken::Info tinfo;
	if (tok.parse(token,tinfo)) return sendInvalidToken(req);
	UserProfile prof = us.loadProfile(UserID(tinfo.userId));
	Value nfo = prof.getHOTPInfo();
	if (nfo.isNull()) req.setError(404,"No HTOP informations are available");
	else req.setResult(nfo);
}


}

