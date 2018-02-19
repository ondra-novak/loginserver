#ifndef SRC_SERVER_RPCINTERFACE_H_
#define SRC_SERVER_RPCINTERFACE_H_

#pragma once

#include <imtjson/rpc.h>
#include <token/usertoken.h>
#include "user_services.h"

namespace loginsrv {

using namespace json;

class RpcInterface{
public:

	static const unsigned int expireAccountCreate = 3*24*60*60;//3 days

	typedef std::function<void(StrViewA,StrViewA, Value)> SendMailFn; //template, email,data
	typedef std::function<bool(StrViewA)> CaptchaFn; //template, email,data

	RpcInterface (UserServices &us,
				  UserToken &tok,
				  const SendMailFn &mail,
				  const CaptchaFn &captcha,
				  const Value &configObj)
			:us(us),tok(tok),mail(mail),captcha(captcha),configObj(configObj) {}

	void registerMethods(RpcServer &srv);



	void rpcRegisterUser(RpcRequest req);
	void rpcLogin(RpcRequest req);
	void rpcTokenParse(RpcRequest req);
	void rpcTokenRefresh(RpcRequest req);
	void rpcTokenRevokeAll(RpcRequest req);
	void rpcSetPassword(RpcRequest req);
	void rpcResetPassword(RpcRequest req);
	void rpcRequestResetPassword(RpcRequest req);
	void rpcGetAccountName(RpcRequest req);
	void rpcLoadAccount(RpcRequest req);
	void rpcSaveAccount(RpcRequest req);
	void rpcGetPublicKey(RpcRequest req);
	void rpcAdminLoadAccount(RpcRequest req);
	void rpcAdminUpdateAccount(RpcRequest req);
	void rpcUserPrepareOTP(RpcRequest req);
	void rpcUserEnableOTP(RpcRequest req);


protected:
	UserServices &us;
	UserToken &tok;
	SendMailFn mail;
	CaptchaFn captcha;
	Value configObj;
	bool firstUser;

private:
	void sendInvalidToken(json::RpcRequest req);

};



}



#endif /* SRC_SERVER_RPCINTERFACE_H_ */
