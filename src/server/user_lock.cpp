/*
 * user_lock.cpp
 *
 *  Created on: Feb 21, 2018
 *      Author: ondra
 */

#include <server/user_lock.h>

namespace loginsrv {

time_t UserLock::isUserLocked(Value user) const {
	Sync _(lock);
	auto itr = lockDb.find(user);
	if (itr == lockDb.end()) return 0;
	else return itr->second;
}

void UserLock::lockUser(Value user, time_t unlockTime) {
	Sync _(lock);
	lockDb[user] = unlockTime;
	highestExpiration = std::max(highestExpiration, unlockTime);
}

void UserLock::unlockUser(Value user, time_t curTime) {
	Sync _(lock);
	if (curTime > highestExpiration) {
		lockDb.clear();
	} else {
		lockDb.erase(user);
	}
}


} /* namespace loginsrv */
