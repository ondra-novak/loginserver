#include "rpcinterface.h"

namespace loginsrv {


void RpcInterface::registerMethods(RpcServer& srv) {


	srv.add("User.create",this,&RpcInterface::rpcRegisterUser);
	srv.add("User.loginPwd",this,&RpcInterface::rpcLogin);
	srv.add("User.setPassword",this,&RpcInterface::rpcSetPassword);
	srv.add("User.resetPassword",this,&RpcInterface::rpcResetPassword);
	srv.add("User.requestResetPassword",this,&RpcInterface::rpcRequestResetPassword);
	srv.add("Account.load",this,&RpcInterface::rpcLoadAccount);
	srv.add("Account.update",this,&RpcInterface::rpcSaveAccount);
	srv.add("Token.parse",this,&RpcInterface::rpcTokenParse);
	srv.add("Token.refresh",this,&RpcInterface::rpcTokenRefresh);
	srv.add("Token.revokeAll",this,&RpcInterface::rpcTokenRevokeAll);
	srv.add("Token.getPublicKey",this,&RpcInterface::rpcGetPublicKey);

}

void RpcInterface::rpcRegisterUser(RpcRequest req) {
	if (!req.checkArgs({"string"})) {
		return req.setArgError();
	}
	StrViewA email = req.getArgs()[0].getString();
	UserProfile prof = us.createUser(email);
	String code = prof.genAccessCode("resetpwd", expireAccountCreate);
	us.storeProfile(prof);
	mail("register", email, Object("code", code));
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
	tok.prepare(tinfo.userId,tinfo);
	req.setResult(tok.create(tinfo));
}

void RpcInterface::rpcGetPublicKey(RpcRequest req) {
	req.setResult(tok.getPublicKey());
}

void RpcInterface::rpcResetPassword(RpcRequest req) {
	if (!req.checkArgs({Object("email","string")("code","string")("password","string")})) {
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
	if (tr == UserProfile::accepted) {
		prof.setPassword(pwd);
		req.setResult(true);
	} else {
		sendInvalidToken(req);
	}
	if (tr == UserProfile::rejected || tr == UserProfile::accepted) {
		us.storeProfile(prof);
	}
}


void RpcInterface::rpcRequestResetPassword(RpcRequest req) {
	if (!req.checkArgs({"string"})) {
		return req.setArgError();
	}
	auto args = req.getArgs();
	StrViewA email = args[0].getString();
	UserID id = us.findUser(email);
	if (id.empty()) return req.setError(404,"Not found");
	UserProfile prof = us.loadProfile(id);
	String code = prof.genAccessCode("resetpwd", expireAccountCreate);
	us.storeProfile(prof);
	mail("resetpwd",email,Object("code", code));

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
	if (!req.checkArgs({"string"})) {
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
	static Value argformat = Value::fromString("{\"_id\":\"optional\",\"_rev\":\"optional\",\"password\":\"optional\",\"%\":\"any\"}");
	if (!req.checkArgs({"string", argformat})) {
		return req.setArgError();
	}
	auto args = req.getArgs();
	StrViewA token = args[0].getString();
	Value update = args[1];
	UserToken::Info tinfo;
	if (tok.parse(token,tinfo) != UserToken::valid) return sendInvalidToken(req);
	UserProfile p = us.loadProfile(tinfo.userId);
	p = Value(p).merge(Object("public",update));
	us.storeProfile(p);
	req.setResult(true);
}

void RpcInterface::sendInvalidToken(RpcRequest req) {
	return req.setError(402, "Invalid token");
}

void RpcInterface::rpcTokenParse(RpcRequest req) {
	if (!req.checkArgs({"string"})) {
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
			  ("refreshExpires", tinfo.refreshExpireTime)
			  ("payload", tinfo.payload);
		break;
	case UserToken::invalid:
		return sendInvalidToken(req);
	}
	req.setResult(result);
}

void RpcInterface::rpcTokenRefresh(RpcRequest req) {
	if (!req.checkArgs({"string"})) {
		return req.setArgError();
	}
	StrViewA token = req.getArgs()[0].getString();
	UserToken::Info tinfo;
	UserToken::Status st = tok.parse(token,tinfo);
	if (st == UserToken::invalid)
		return sendInvalidToken(req);


	if (tinfo.expireTime == tinfo.created)
		return req.setError(403,"Token cannot be refreshed");

	UserProfile prof = us.loadProfile(UserID(tinfo.userId));
	std::size_t revokeTime = prof["tokenRevoke"].getUInt();
	String newtok = tok.refresh(tinfo,revokeTime);
	if (newtok.empty()) {
		return req.setError(410, "Token has been revoked");
	} else {
		req.setResult(newtok);
	}
}

void RpcInterface::rpcLogin(RpcRequest req) {
	if (!req.checkArgs({"string","string",{"boolean","optional"}})) {
		return req.setArgError();
	}
	Value args = req.getArgs();
	StrViewA email = args[0].getString();
	StrViewA password = args[1].getString();
	bool remember = args[2].getBool();

	try {
		UserID userid = us.findUser(email);
		UserProfile prof = us.loadProfile(userid);
		if (prof.checkPassword(password)) {

			UserToken::Info tnfo;
			tok.prepare(userid, tnfo);
			if (!remember) tnfo.refreshExpireTime = tnfo.expireTime;
			String token = tok.create(tnfo);
			String choosenConfig (prof["config"]);
			Value cfg = configObj[choosenConfig];
			if (!cfg.defined()) {
				cfg = configObj[""];
			}

			Object res;
			res("token", token)
			   ("expires", tnfo.expireTime)
			   ("config", cfg);

			req.setResult(res);
		} else {
			req.setError(401,"Invalid credentials");
		}
	} catch (...) {
		req.setError(401,"Invalid credentials");
	}
}

void RpcInterface::rpcSetPassword(RpcRequest req) {
	if (!req.checkArgs({"string","string","string"})) {
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
		req.setResult(true);
	}
}


}
