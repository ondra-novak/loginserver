#pragma once
#include "shared/vla.h"

#include "shared/stringview.h"

class GoogleOTP {
public:

	typedef ondra_shared::BinaryView BinaryView;
	typedef ondra_shared::StrViewA StrViewA;
	typedef ondra_shared::VLA<unsigned char, 20> Secret;

	///Initialize GoogleOTP class with binary secret
	/**
	 * @param secret binary secret
	 */
	GoogleOTP(BinaryView secret);
	///Initialize GoogleOTP class with base32 secret
	/**
	 * @param base32 base32 secret
	 */
	GoogleOTP(StrViewA base32);

	///Generates code for given counter
	/**
	 * @param counter counter
	 * @return code
	 */
	unsigned int getCode(unsigned int counter) const;
	///Generates TOTP code
	/**
	 * @return code based on current time
	 */
	unsigned int getTimeCode() const;
	///Checks code
	/**
	 *
	 * @param counter counter. Set to 0 for the first time call. Function adjusts
	 *    the counter for the next call.
	 * @param code entered code by user
	 * @param gap how many codes to check, because user can generate codes without using
	 * them.
	 * @retval true valid (counter adjusted)
	 * @retval false invalid (counter did not changed)
	 */
	bool checkCode(unsigned int &counter, unsigned int code, unsigned int gap=10) const;
	///Checks time code (TOTP)
	/**
	 *
	 * @param code code entered by user
	 * @param accuracy count of codes around current time.
	 * @retval true valid (counter adjusted)
	 * @retval false invalid (counter did not changed)
	 */
	bool checkTimeCode(unsigned int code, unsigned int accuracy = 2) const;


	BinaryView getSecret() const;

	unsigned int storeSecretBase32(char *output) const;
protected:
	Secret secret;

};
