#include <token/usertoken.h>
#include <cstdio>
#include <iostream>
#include <cstdlib>
#include "token.h"

using namespace loginsrv;

int main(int argc, char **argv) {

Token t1(Token::privateKey, "abcd1256");
t1.setPreloadedKeys({"userId","roles","created"});
std::cout << "Public key: " << t1.getPublicKey() << std::endl;

Token t2(Token::publicKey, t1.getPublicKey());
t2.setPreloadedKeys(t1.getPreloadedKeys());
t2.setEncoder(json::urlEncoding,"|");
t1.setEncoder(json::urlEncoding,"|");

Value payload = Value::fromString("{\"userId\":12345,\"roles\":[\"user\"],\"created\":12314423423}");
String token = t1.createToken(payload);
std::cout << "Payload: " << payload.toString() << std::endl;
std::cout << "Token: " << token << std::endl;

Value extracted = t2.parseToken(token);
std::cout << "Extracted: " << extracted.toString() << std::endl;

extracted = t2.parseToken("qweuiqiojdowoqw.qweiqwpeoqkcxiew");
std::cout << "Extracted2: " << extracted.toString() << std::endl;

extracted = t2.parseToken("U4AsfzD_3YFhRHVzZXKCKzkw.MDwCHC_PERHlinDCr9z33TCGUlsYuI_0bsJxwiNoc50CHGIQgZSy3sv7gM6oxlObijb4rwBLOce7SFc5ric");
std::cout << "Extracted3: " << extracted.toString() << std::endl;

extracted = t2.parseToken("U4BsfzD_3YFhRHVzZXKCKzkw.MDwCHC_PERHlinDCr9z33TCGUlsYuI_0bsJxwiNoc50CHGIQgZSy3sv7gM6oxlObijb4rwBLOce7SFc5ric");
std::cout << "Extracted4: " << extracted.toString() << std::endl;

std::cout << "-------------" << std::endl;

UserToken ut1(Token::privateKey, "UserTokenTest");

String userToken = ut1.create(ut1.prepare("Bredy","test",Value(),300));
std::cout << "User token: " << userToken << std::endl;

UserToken ut2(Token::publicKey, ut1.getPublicKey());
UserToken::Info nfo;
UserToken::Status status = ut2.parse(userToken, nfo);
if (status == UserToken::valid) {
	std::cout << "User Id:" << nfo.userId.toString() << std::endl;
	std::cout << "Created:" << nfo.created << std::endl;
	std::cout << "Expires:" << nfo.expireTime << std::endl;
	std::cout << "Purpose:" << nfo.purpose<< std::endl;
}

return 0;
}
