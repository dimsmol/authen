"use strict";
var errh = require('ncbt').errh;
var ops = require('ops');


// NOTE it's an abstract class
var Revoker = function (opt_options) {
	this.options = this.createOptions(opt_options);
};

Revoker.prototype.createOptions = function (opt_options) {
	return ops.cloneWithDefaults(opt_options, this.getDefaultOptions());
};

Revoker.prototype.getDefaultOptions = function () {
		return {
			postRevocationTrustDelay: 5 * 60 * 1000 // 5 minites in ms
		};
};

Revoker.prototype.getLastRevokationTime = function (cb) {
	throw new Error('Abstract method call');
};

Revoker.prototype.checkRevoked = function (tokenData, cb) {
	var self = this;
	this.getLastRevocationTime(errh(function (lastRevokationTime) {
		var momentToCheck = lastRevokationTime;
		if (tokenData.isRenewal) {
			// don't trust renewals issued too near to revokation moment
			momentToCheck -= self.options.postRevocationTrustDelay;
		}
		var isRevoked = (tokenData.issued < momentToCheck);
		cb(null, isRevoked);
	}, cb));
};


module.exports = Revoker;
