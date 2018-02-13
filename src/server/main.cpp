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


using ondra_shared::StdLogFile;
using ondra_shared::IniConfig;
using namespace couchit;
using namespace json;
using namespace simpleServer;




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
	StrViewA hostMapping = serverCfg.mandatory["mapHosts"].getString();
	StrViewA straddr =  serverCfg.mandatory["bind"].getString();
	unsigned int threads  = serverCfg.mandatory["threads"].getUInt();
	unsigned int dispatchers  = serverCfg.mandatory["dispatchers"].getUInt();
	simpleServer::NetAddr addr = simpleServer::NetAddr::create(straddr,52123);


	RpcHttpServer server(addr, threads, dispatchers);

	server.setHostMapping(String(hostMapping));

	svc.changeUser(serverCfg["user"].getString());

	LogLevelToStrTable levelToStr;

	(new StdLogFile(serverCfg["logFile"].getPath(), levelToStr.fromString(serverCfg["logLevel"].getString(), LogLevel::info)))->setDefault();

	svc.enableRestart();

	std::string client  = serverCfg["webClient"].getPath();
	server.addRPCPath("/RPC", client);


	server.add_listMethods("methods");
	server.add_ping("ping");



	server.start();

	svc.dispatch();


	return 0;


	});


}
