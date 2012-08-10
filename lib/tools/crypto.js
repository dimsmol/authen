"use strict";
var constantTimeEquals = function (s1, s2) {
	var result = false;
	if (s1.length == s2.length) {
		result = true;
		for (var i = 0; i < s1.length; i++) {
			if (s1[i] != s2[i]) {
				result = false;
			}
		}
	}
	return result;
};


module.exports = {
	constantTimeEquals: constantTimeEquals
};
