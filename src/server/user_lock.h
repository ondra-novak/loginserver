#pragma once
#include <imtjson/value.h>
#include <mutex>
#include <unordered_map>

namespace loginsrv {

using namespace json;

class UserLock {
public:

	time_t isUserLocked(Value user) const;
	void lockUser(Value user, time_t unlockTime);
	void unlockUser(Value user, time_t curTime);

protected:

	mutable std::mutex lock;
	typedef std::unique_lock<std::mutex> Sync;

	std::unordered_map<Value, time_t> lockDb;
	time_t highestExpiration = 0;

};

} /* namespace loginsrv */


