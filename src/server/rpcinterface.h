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


	class IServices {
	public:
		virtual ~IServices() {}
		///Formatting and mailing service
		/**
		 * @param email target e-mail (recepient)
		 * @param templateName name of the template
		 * @param templateData data of the template
		 */
		virtual void sendMail(const StrViewA email,
				const StrViewA templateName,
				const Value &templateData) = 0;
		///Verifies the captcha
		/**
		 * @param response captcha response sent by the user
		 * @retval true captcha verified successfully
		 * @retval false verification failed.
		 */
		virtual bool verifyCaptcha(const StrViewA response) = 0;

		///Generates label for OTP.
		/**
		 * @param profile user's profile
		 * @return OTP label
		 */
		virtual String getOTPLabel(const UserProfile &profile)  = 0;

		virtual Value getUserConfig(const StrViewA key) = 0;
	};

	struct Config {
		unsigned int mailCodeExpiration_sec;
		unsigned int rootTokenExpiration_sec;
		unsigned int refreshTokenExpiration_sec;

	};


	static const unsigned int expireAccountCreate = 3*24*60*60;//3 days


	RpcInterface (UserServices &us,
				  UserToken &tok,
				  IServices &svc,
				  const Config &cfg);


	void registerMethods(RpcServer &srv);



	void rpcRegisterUser(RpcRequest req);
	void rpcLogin(RpcRequest req);
	void rpcTokenParse(RpcRequest req);
	void rpcTokenCreate(RpcRequest req);
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
	void rpcUserCheckOTP(RpcRequest req);
	void rpcUserVerifyOTP(RpcRequest req);


protected:
	UserServices &us;
	UserToken &tok;
	IServices &svc;
	Config cfg;
	bool firstUser;

private:
	void sendInvalidToken(json::RpcRequest req);

};



}



#endif /* SRC_SERVER_RPCINTERFACE_H_ */
