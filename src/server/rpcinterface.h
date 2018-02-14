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

	RpcInterface (UserServices &us, UserToken &tok, const SendMailFn &mail)
			:us(us),tok(tok),mail(mail) {}

	void registerMethods(RpcServer &srv);



	void rpcRegisterUser(RpcRequest req);
	void rpcLogin(RpcRequest req);
	void rpcTokenParse(RpcRequest req);
	void rpcTokenRefresh(RpcRequest req);
	void rpcTokenRevokeAll(RpcRequest req);
	void rpcSetPassword(RpcRequest req);


protected:
	UserServices &us;
	UserToken &tok;
	SendMailFn mail;

private:
	void sendInvalidToken(json::RpcRequest req);
};



}



#endif /* SRC_SERVER_RPCINTERFACE_H_ */
