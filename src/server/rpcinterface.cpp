#include "rpcinterface.h"

namespace loginsrv {


void RpcInterface::registerMethods(RpcServer& srv) {


	srv.add("User.create",this,&RpcInterface::rpcRegisterUser);
	srv.add("User.loginPwd",this,&RpcInterface::rpcLogin);
	srv.add("User.setPassword",this,&RpcInterface::rpcSetPassword);
	srv.add("Token.parse",this,&RpcInterface::rpcTokenParse);
	srv.add("Token.refresh",this,&RpcInterface::rpcTokenRefresh);
	srv.add("Token.revokeAll",this,&RpcInterface::rpcTokenRevokeAll);

}

void RpcInterface::rpcRegisterUser(RpcRequest req) {
	if (!req.checkArgs({"string"})) {
		return req.setArgError();
	}
	StrViewA email = req.getArgs()[0].getString();
	UserID uid = us.createUser(email);
	UserToken::Info ses;
	tok.prepare(uid, ses);
	ses.expireTime = ses.created;
	ses.refreshExpireTime = ses.created+expireAccountCreate;
	ses.payload = "create";
	String token = tok.create(ses);
	mail("register",email, Object("token", token));
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
	if (!req.checkArgs({"string"."string"})) {
		return req.setArgError();
	}

}

void RpcInterface::rpcSetPassword(RpcRequest req) {
	if (!req.checkArgs({"string","string"})) {
		return req.setArgError();
	}
	StrViewA token = req.getArgs()[0].getString();
	StrViewA password = req.getArgs()[1].getString();
	UserToken::Info tinfo;
	if (tok.parse(token,tinfo)) return sendInvalidToken(req);

	UserProfile prof = us.loadProfile(UserID(tinfo.userId));
	prof.setPassword(password);
	us.storeProfile(prof);
	req.setResult(true);
}


}
