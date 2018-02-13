/*
 * Token.h
 *
 *  Created on: 13. 2. 2018
 *      Author: ondra
 */

#ifndef SRC_TOKEN_TOKEN_H_
#define SRC_TOKEN_TOKEN_H_
#include <openssl/ec.h>
#include "shared/stringview.h"
#include "imtjson/json.h"

#pragma once

namespace loginsrv {

using ondra_shared::StrViewA;
using json::Value;
using json::String;
using ondra_shared::StringView;

///Easy tokens
/** Tokens are signed by ECDSA.
 *
 * format of the token
 * <base64-payload>.<base64-signature>
 * payload = just json
 * signature = standarized ECDSA signature
 */
class Token {
public:

	enum KeyType {
		privateKey,
		publicKey
	};

	///Initialize the class with specified key
	/**
	 *
	 * @param type type of key used. See KeyType for more information
	 * @param keyBase64 a key as base64 string
	 */
	Token(KeyType type, const StrViewA &keyBase64);
	~Token();
	///Creates copy of token object
	Token(const Token& other);
	///You cannot use assigment
	Token &operator=(const Token& other) = delete;

	///Retrieves or generates the public key which can be used to initialize Token()
	String getPublicKey() const;

	///Creates token from payload
	/**
	 * @param payload payload in json
	 * @return signed token
	 * @exception std::runtime_error Token is initialized with public key, which cannot be used to create tokens
	 */
	String createToken(Value payload) const;

	///Parses token
	/**
	 * @param token token as string
	 * @return parsed value. Function returns undefined in case that token is invalid or corrupted (or when digital
	 * signature doesn't match]
	 */
	Value parseToken(const StrViewA &token);


	bool setPublicKey(const StrViewA &keyBase64);

	void setPreloadedKeys(const StringView<String> &keys);

	StringView<String> getPreloadedKeys() const;

	void setEncoder(json::BinaryEncoding encoder, StrViewA separator);

protected:

	static StrViewA defaultSeparator;

	EC_KEY *key;
	std::vector<String> preloadedKeys;
	json::BinaryEncoding encoder = json::base64url;
	StrViewA separator = defaultSeparator;

};

} /* namespace loginsrv */

#endif /* SRC_TOKEN_TOKEN_H_ */
