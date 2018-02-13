/*
 * session.cpp
 *
 *  Created on: Feb 12, 2018
 *      Author: ondra
 */

#include "session.h"

using namespace json;

Status Session::unpackSession(ondra_shared::StrViewA sessionStr, Info& nfo) {

Value vb = base64url->decodeBinaryValue(sessionStr);
Binary b = vb.getBinary(base64url);
size_t pos = 0;
auto reader = [&]{if (pos >= b.length) return -1; else return (int)(b.data[pos++]);}
Value sesdata = Value::parseBinary(reader, base64);
Value signature = sesdata[0];
Value timeCreates = sesdata[1];
Value deltaExpires = sesdata[2];
Value deltaExtend = sesdata[3];
Value user = sesdata[4];
nfo.created = timeCreates.getUInt();
nfo.expires = nfo.created+deltaExpires.getUInt();
nfo.extend = nfo.expires+deltaExtend.getUInt();
nfo.userid = user.getString();

String sign2 = generateSignature(nfo);



}

std::string Session::packSession(const Info& info) {
}

Session::Session(const std::string& secret) {
}
