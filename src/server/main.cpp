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
using namespace couchit;
using namespace json;
using namespace simpleServer;
using namespace loginsrv;


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

	std::string client  = serverCfg.mandatory["web_client"].getPath();
	server.addRPCPath("/RPC", client);


	server.add_listMethods("methods");
	server.add_ping("ping");

	auto loginCfg = config["login"];
	Value privateKey = loginCfg.mandatory["private_key"].getString();
	std::string userConfig = loginCfg.mandatory["user_config"].getPath();
	std::string sendCmd = loginCfg.mandatory["mail_svc"].getString();
	std::string templatePrefix = loginCfg["mail_template_prefix"].getString();


	Value userConfigJson = readUserConfig(userConfig);

	UserToken tok(Token::privateKey, String(privateKey));
	tok.setExpireTime(loginCfg.mandatory["token_expiration"].getUInt());
	tok.setRefreshExpireTime(loginCfg.mandatory["token_refresh_expiration"].getUInt());
	UserServices us(couchdb);
	RpcInterface ifc(us, tok, [=](StrViewA templt,StrViewA email, Value payload){
		Value req = Object("template",String({templatePrefix,templt}))
				("recepient", email)
				("data", payload);
		ondra_shared::logDebug("Send mail: $1 - $2", sendCmd, req.toString());
		FILE *f = popen(sendCmd.c_str(),"w");
		if (f == nullptr) {
			ondra_shared::logError("Cannot execute command: $1",sendCmd);
		} else {
			req.toFile(f);
			int res = pclose(f);
			if (res) ondra_shared::logError("Unexpected exit status for command: $1 - exit $2",sendCmd, res);
		}
		}, userConfigJson);

	ifc.registerMethods(server);


	server.start();

	svc.dispatch();


	return 0;


	});


}
