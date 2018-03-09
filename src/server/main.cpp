/*
 * main.cpp
 *
 *  Created on: 11. 7. 2017
 *      Author: ondra
 */


#include <thread>
#include <couchit/changes.h>
#include <imtjson/rpc.h>
#include <rpc/rpcServer.h>
#include <shared/stdLogFile.h>
#include <simpleServer/address.h>
#include <simpleServer/http_server.h>
#include <simpleServer/abstractService.h>
#include <simpleServer/http_filemapper.h>
#include <simpleServer/logOutput.h>
#include <shared/ini_config.h>
#include <token/usertoken.h>
#include "rpcinterface.h"
#include "user_services.h"


using ondra_shared::StdLogFile;
using ondra_shared::IniConfig;
using ondra_shared::StrViewA;
using namespace couchit;
using namespace json;
using namespace simpleServer;
using namespace loginsrv;

static Value customRules = json::Value::fromString(R"json(
{
"Email":["explode","@",[[2],"Username","Domain"]],
"Username":"[a-z-A-Z.0-9_+\"]",
"Domain":["explode",".",[[2],"DomainPart","DomainPart","DomainPart"]],
"DomainPart":"[a-z-0-9]",
"Token":["explode",".",[[2],"base64url","base64url"]],
"Code":["explode","-",[[2],"digits","digits","digits"]],
"Password":["all","string",["minsize",8]],
"PurposeItem":["all","[a-zA-Z0-9_]",["!","Refresh"]],
"PurposeList":[[],"PurposeItem"],
"Purpose":["Refresh","PurposeItem","PurposeList",[[2],"Refresh","PurposeList"]],
"Refresh":"'refresh"
}

)json");



static Value readUserConfig(const std::string &name) {

	std::ifstream inf(name, std::ios::in);
	if (!inf) {
		std::string error = "Can't read user config: " + name;
		throw std::runtime_error(error);
	}
	try {
		return Value::fromStream(inf);
	} catch (std::exception &e) {
		std::string error("Failed to read user config: ");
		error.append(e.what());
		throw std::runtime_error(error);
	}
}


class Svcs: public RpcInterface::IServices {
public:
	Svcs(
			const std::string &templatePrefix,
			const std::string &sendCmd,
			const std::string &captchaCmd,
			const std::string &otpissuer,
			const std::string &reportCmd,
			const Value &usercfg
		):templatePrefix(templatePrefix)
		,sendCmd(sendCmd)
		,captchaCmd(captchaCmd)
		,otpissuer(otpissuer)
		,reportCmd(reportCmd)
		,usercfg(usercfg)
		,reportF(nullptr) {}

	~Svcs() {
		if (reportF) pclose(reportF);
	}

	virtual void sendMail(const StrViewA email,
			const StrViewA templateName,
			const Value &templateData) override;



	virtual bool verifyCaptcha(const StrViewA response)override;

	virtual String getOTPLabel(const UserProfile &profile)override;


	virtual Value getUserConfig(const StrViewA key) override;

	virtual void report(const Value userId, const StrViewA &action, Value data) override;

protected:

	std::string templatePrefix;
	std::string sendCmd;
	std::string captchaCmd;
	std::string otpissuer;
	std::string reportCmd;
	Value usercfg;

	std::mutex lock;
	FILE *reportF;


};

void Svcs::sendMail(const StrViewA email,
		const StrViewA templateName,
		const Value &templateData) {

	if (email.empty()) return;
	Value req = Object("template",String({templatePrefix,templateName}))
			("recepient", email)
			("data", templateData);
	ondra_shared::logDebug("Send mail: $1 - $2", sendCmd, req.toString());
	if (!sendCmd.empty()) {
		FILE *f = popen(sendCmd.c_str(),"w");
		if (f == nullptr) {
			ondra_shared::logError("Cannot execute command: $1",sendCmd);
		} else {
			req.toFile(f);
			fputs("\n",f);
			int res = pclose(f);
			if (res) ondra_shared::logError("Unexpected exit status for command: $1 - exit $2",sendCmd, res);
		}
	}
}



bool Svcs::verifyCaptcha(const StrViewA response) {

	ondra_shared::logDebug("Check captcha: $1 - $2", captchaCmd, response);
	if (!captchaCmd.empty()) {
		FILE *f = popen(captchaCmd.c_str(),"w");
		if (f == nullptr) {
			ondra_shared::logError("Cannot execute command: $1",captchaCmd);
			return false;
		} else {
			fwrite(response.data,response.length,1,f);
			fputs("\n",f);
			int res = pclose(f);
			return res == 0;
		}
	}
	return true;

}

String Svcs::getOTPLabel(const UserProfile &profile) {
	return String(StrViewA(otpissuer));

}

Value Svcs::getUserConfig(const StrViewA key) {
	Value c = usercfg[key];
	if (c.defined()) return c;
	return usercfg[""];
}

void Svcs::report(const Value userId, const StrViewA &action, Value data)  {
	Object repObj;
	time_t now;
	time(&now);
	repObj("time", std::size_t(now))
		  ("user", userId)
		  ("event", action)
		  ("data", data);
	std::lock_guard<std::mutex> _(lock);
	if (reportF == nullptr) {
		reportF = popen(reportCmd.c_str(),"w");
		if (reportF == nullptr) {
			logError("Can't initialize report stream. Cmd: $1 - error $2", reportCmd, errno);
			return;
		}
	}
	Value(repObj).toFile(reportF);
	if (fputs("\n",reportF) < 0 || fflush(reportF) < 0) {
		unsigned int res = pclose(reportF);
		logError("The report process (cmd: $1) has died with exit code: $2", reportCmd, res);
		reportF = nullptr;
	}
}




int main(int argc, char **argv) {

	(new StdLogProviderFactory())->setDefault();


	return

	simpleServer::ServiceControl::create(argc, argv, "loginsrv",
			[&](simpleServer::ServiceControl svc, StrViewA, simpleServer::ArgList lst) {



	if (lst.length != 1) {
		std::cerr << "need path to config";
		return 1;
	}



	IniConfig config;
	config.load(lst[0]);



	couchit::Config couchcfg;
	auto dbCfg = config["database"];
	couchcfg.authInfo.username = dbCfg.mandatory["user"].getString();
	couchcfg.authInfo.password = dbCfg.mandatory["password"].getString();
	couchcfg.baseUrl =dbCfg.mandatory["url"].getString();
	couchcfg.databaseName = dbCfg.mandatory["name"].getString();

	CouchDB couchdb(couchcfg);


	auto serverCfg = config["server"];

	LogLevelToStrTable levelToStr;
	(new StdLogFile(serverCfg["log_file"].getPath(), levelToStr.fromString(serverCfg["log_level"].getString(), LogLevel::info)))->setDefault();

	StrViewA hostMapping = serverCfg.mandatory["map_hosts"].getString();
	StrViewA straddr =  serverCfg.mandatory["bind"].getString();
	unsigned int threads  = serverCfg.mandatory["threads"].getUInt();
	unsigned int dispatchers  = serverCfg.mandatory["dispatchers"].getUInt();
	simpleServer::NetAddr addr = simpleServer::NetAddr::create(straddr,52123);


	RpcHttpServer server(addr, threads, dispatchers);

	server.setHostMapping(String(hostMapping));

	svc.changeUser(serverCfg["user"].getString());



	svc.enableRestart();

	RpcHttpServer::Config cfg;
	cfg.enableConsole = serverCfg["rpc_enableConsole"].getUIntDefVal(1) != 0;
	cfg.maxReqSize = serverCfg["rpc_maxReqSize"].getUIntDefVal(0);
	server.addRPCPath("/RPC", cfg);


	server.add_listMethods("methods");
	server.add_ping("ping");

	auto loginCfg = config["login"];
	Value privateKey = loginCfg.mandatory["private_key"].getString();
	std::string userConfig = loginCfg.mandatory["user_config"].getPath();
	std::string sendCmd = loginCfg.mandatory["mail_svc"].getPath();
	std::string templatePrefix = loginCfg["mail_template_prefix"].getString();
	std::string captcha = loginCfg["captcha_svc"].getPath();
	std::string otpIssuer = loginCfg.mandatory["otp_issuer"].getString();
	std::string reportSvc = loginCfg.mandatory["report_svc"].getPath();


	Value userConfigJson = readUserConfig(userConfig);



	UserToken tok(Token::privateKey, String(privateKey));
	RpcInterface::Config ifccfg;
	ifccfg.mailCodeExpiration_sec = loginCfg.mandatory["mail_code_expires"].getUInt();
	ifccfg.refreshTokenExpiration_sec = loginCfg.mandatory["refresh_token_expires"].getUInt();
	ifccfg.rootTokenExpiration_sec = loginCfg.mandatory["token_expires"].getUInt();
	ifccfg.userLockWait = loginCfg.mandatory["login_failure_lock_time"].getUInt();

	UserServices us(couchdb);
	Svcs ifcsvc(templatePrefix,sendCmd,captcha,otpIssuer,reportSvc,userConfigJson);


	RpcInterface ifc(us, tok, ifcsvc, ifccfg);



	server.setCustomValidationRules(customRules);
	ifc.registerMethods(server);

	server.addPath("/web",HttpFileMapper("web/","index.html"));

	server.start();

	svc.dispatch();


	return 0;


	});


}
