/*
 * Token.cpp
 *
 *  Created on: 13. 2. 2018
 *      Author: ondra
 */

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>

#include "token.h"
#include <imtjson/binjson.tcc>

namespace loginsrv {

#define EC_CURVE_NAME NID_secp224r1

using ondra_shared::BinaryView;
using json::base64url;
using json::Binary;

StrViewA Token::defaultSeparator(".");

bool static inline regenerate_key(EC_KEY* eckey, BIGNUM* priv_key) // @suppress("Name convention for function")
{
    if (!eckey) return false;

    const EC_GROUP *group = EC_KEY_get0_group(eckey);

    bool rval = false;
    EC_POINT* pub_key = NULL;
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) goto err;

    pub_key = EC_POINT_new(group);
    if (!pub_key) goto err;

    if (!EC_POINT_mul(group, pub_key, priv_key, NULL, NULL, ctx)) goto err;

    EC_KEY_set_private_key(eckey, priv_key);
    EC_KEY_set_public_key(eckey, pub_key);

    rval = true;

err:
    if (pub_key) EC_POINT_free(pub_key);
    if (ctx) BN_CTX_free(ctx);
    return rval;
}

class HashDigest: public BinaryView {
public:
	HashDigest(const BinaryView &v):BinaryView(digest, SHA224_DIGEST_LENGTH) {
		SHA256_CTX ctx;
		SHA224_Init(&ctx);
		SHA224_Update(&ctx,v.data, v.length);
		SHA224_Final(digest,&ctx);
	}

protected:
	unsigned char digest[SHA224_DIGEST_LENGTH];

};

String Token::createToken(Value payload) const {
	std::basic_string<unsigned char> buffer;
	auto writter = [&](char c){buffer.push_back(c);};
	json::BinarySerializer<decltype(writter)> ser(writter, json::compressKeys);
	for (auto &&x: preloadedKeys) ser.preloadKey(x);
	ser.serialize(payload);

	HashDigest digest(BinaryView(buffer.data(), buffer.length()));

	unsigned int reqsize = ECDSA_size(key);
	unsigned char signature[reqsize];
	if (!ECDSA_sign(0, digest.data, digest.length, signature, &reqsize, key)) {
		return String();
	}
	String ss = String(encoder->encodeBinaryValue(BinaryView(signature,reqsize)));
	String srb = String(encoder->encodeBinaryValue(BinaryView(buffer.data(), buffer.length())));
	return String({srb,separator,ss});
}

Value Token::parseToken(const StrViewA& token) {
	auto sep = token.indexOf(separator);
	if (sep == token.npos) return json::undefined;

	StrViewA payload = token.substr(0,sep);
	StrViewA signature = token.substr(sep+separator.length);

	Binary binpayload = encoder->decodeBinaryValue(payload).getBinary(encoder);
	Binary binsignature = encoder->decodeBinaryValue(signature).getBinary(encoder);

	HashDigest digest(binpayload);


	int res = ECDSA_verify(0,digest.data, digest.length, binsignature.data, binsignature.length, key);
	if (res) {

		try {
			std::size_t pos = 0;
			auto reader = [&] {return pos >= binpayload.length?-1:(int)binpayload[pos++];};
			json::BinaryParser<decltype(reader)> parser(reader, json::base64);
			for (auto &&x: preloadedKeys) parser.preloadKey(x);
			return parser.parse();
		} catch (...) {
			return json::undefined;
		}
	} else {
		return json::undefined;
	}
}

bool Token::setPublicKey(const StrViewA &keyBase64) {
	Value k = encoder->decodeBinaryValue(keyBase64);
	Binary b = k.getBinary(encoder);


	const unsigned char *data = b.data;
	EC_KEY *nwkey = o2i_ECPublicKey(&key,&data, b.length);
	if (nwkey == nullptr) {
		return false;
	}
	if (nwkey != key) {
		EC_KEY_free(key);
		key = nwkey;
	}
	return true;
}


static std::shared_ptr<BIGNUM> parsePrivateKey(json::BinaryEncoding encoder, const StrViewA &keyBase64) {
	Value k = encoder->decodeBinaryValue(keyBase64);
	Binary b = k.getBinary(encoder);
	BIGNUM* bn = BN_bin2bn(b.data, b.length, BN_new());
	return std::shared_ptr<BIGNUM>(bn, &BN_free);
}


Token::Token(KeyType type, const StrViewA &keyBase64) {
	key = EC_KEY_new_by_curve_name(EC_CURVE_NAME);
	if (key == nullptr) throw std::runtime_error("Token: EC_KEY_new_by_curve_name failed");
	switch (type) {
	case publicKey:setPublicKey(keyBase64);break;
	case privateKey: regenerate_key(key, parsePrivateKey(encoder,keyBase64).get());break;
	}
}



Token::~Token() {
	EC_KEY_free(key);
}

String Token::getPublicKey() const{
	EC_KEY_set_conv_form(key, POINT_CONVERSION_COMPRESSED);
	int nSize = i2o_ECPublicKey(key, NULL);
	unsigned char binpubkey[nSize];
	unsigned char *pbinpk = binpubkey;
	if (i2o_ECPublicKey(key, &pbinpk) != nSize) return String();

	return String(encoder->encodeBinaryValue(BinaryView(binpubkey, nSize)));
}

void Token::setPreloadedKeys(const StringView<String>& keys) {
	preloadedKeys.clear();
	preloadedKeys.reserve(keys.length);
	for (auto &&x: keys) preloadedKeys.push_back(x);
}

Token::Token(const Token& other):preloadedKeys(other.preloadedKeys) {
	key = EC_KEY_new();
	EC_KEY_copy(key, other.key);
}

StringView<String> Token::getPreloadedKeys() const {
	return StringView<String>(preloadedKeys.data(), preloadedKeys.size());
}

void Token::setEncoder(json::BinaryEncoding encoder, StrViewA separator) {
	this->encoder = encoder;
	this->separator = separator;
}

} /* namespace loginsrv */

