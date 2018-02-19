#include <openssl/hmac.h>
#include "ga.h"
#include "base32.h"

GoogleOTP::GoogleOTP(BinaryView secret):secret(secret) {

}

GoogleOTP::GoogleOTP(StrViewA base32):secret(base32.length*5/8) {
	base32_decode(reinterpret_cast<const uint8_t *>(base32.data), secret.data, secret.length);

}

unsigned int GoogleOTP::getCode(unsigned int counter) const {

	uint8_t challenge[8];
	for (int i = 8; i--; counter >>= 8) {
		challenge[i] = uint8_t(counter & 0xFF);
	}


	unsigned char digest[50];
	unsigned int digestLen = 50;

	HMAC(EVP_sha1(),secret.data, secret.length, challenge, 8, digest,&digestLen);
	int offset = digest[digestLen - 1] & 0xF;

	// Compute the truncated hash in a byte-order independent loop.
	unsigned int truncatedHash = 0;
	for (int i = 0; i < 4; ++i) {
		truncatedHash <<= 8;
		truncatedHash  |= digest[offset + i];
	}

	// Truncate to a smaller number of digits.
	truncatedHash &= 0x7FFFFFFF;
	truncatedHash %= 1000000;

	return truncatedHash;
}

unsigned int GoogleOTP::getTimeCode() const {
	time_t now;
	time(&now);
	return getCode(now/30);
}

bool GoogleOTP::checkCode(unsigned int& counter, unsigned int code, unsigned int gap) const {

	for (unsigned int i = 0; i < gap; i++) {
		unsigned int c = getCode(i+counter);
		if (c == code) {
			counter = counter+i+1;
			return true;
		}
	}
	return false;

}

bool GoogleOTP::checkTimeCode(unsigned int code, unsigned int accuracy) const {

	time_t c;
	time(&c);
	if (getCode(c) == code) return true;
	for (unsigned int i = 1; i < accuracy; i++) {
		if (getCode(c-i) == code || getCode(c+i) == code) return true;
	}
	return false;

}

GoogleOTP::BinaryView GoogleOTP::getSecret() const {
	return secret;
}

unsigned int GoogleOTP::storeSecretBase32(char* output) const {
	unsigned int outputLen = (secret.length+4)*8/5;
	if (output != nullptr) {
		base32_encode(secret.data,secret.length, reinterpret_cast<uint8_t *>(output), outputLen);
	}
	return outputLen;
}
