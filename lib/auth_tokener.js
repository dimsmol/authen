"use strict";
var inherits = require('util').inherits;
var Tokener = require('./tokener');


var AuthTokener = function (opt_options) {
	Tokener.call(this);

	this.prefix = opt_options && opt_options.prefix || ''; // NOTE cannot contain separator
	this.flagToKey = null;
};
inherits(AuthTokener, Tokener);

// api

AuthTokener.prototype.createToken = function (identityStr, options, cb) {
	// options available:
	// isRenewal, useCookies, isSessionLifetime, useLimitedToken
	var issued = this.getIssued();
	var issuedStr = this.stringifyIssued(issued);

	var token = this.createSingleToken(identityStr, issuedStr, options);
	if (token == null) {
		cb(new Error('Could not create token, possibly configuration problem'));
	}
	else {
		var limitedToken = null;
		if (options.useCookies && options.useLimitedToken) {
			limitedToken = this.createSingleToken(identityStr, issuedStr, {
				isLimited: true
			});
		}
		cb(null, {
			token: token,
			limitedToken: limitedToken,
			issued: issued
		});
	}
};

AuthTokener.prototype.renewToken = function (tokenData, useLimitedToken, cb) {
	// tokenData - as encoded to token by createToken
	this.createToken(tokenData.identityStr, {
		isRenewal: true,
		useLimitedToken: useLimitedToken,
		useCookies: tokenData.useCookies,
		isSessionLifetime: tokenData.isSessionLifetime
	}, cb);
};

AuthTokener.prototype.parseToken = function (token, additionalToken, cb) {
	var data = this.parseSingleToken(token);
	if (data != null && data.isLimited) {
		var limitedTokenData = data;
		data = this.parseSingleToken(additionalToken);
		if (data != null) {
			if (data.issued != limitedTokenData.issued || data.identityStr != limitedTokenData.identityStr) {
				data = null;
			}
		}
	}
	cb(null, data);
};

// internal

AuthTokener.prototype.createSingleToken = function (identityStr, issuedStr, options) {
	var data = this.packData(identityStr, issuedStr, options);
	return this.createTokenByPacked(data, this.prefix);
};

AuthTokener.prototype.parseSingleToken = function (token) {
	var data = this.parseTokenToPacked(token);
	return this.unpackData(data);
};

// data

AuthTokener.prototype.packData = function (identityStr, issuedStr, options) {
	options = options || {};
	var flags = this.stringifyFlags(options);
	return this.pack(['', issuedStr, flags, identityStr]);
};

AuthTokener.prototype.unpackData = function (data) {
	var result = null;
	var unpacked = this.unpack(this.ensureString(data), '', ['issued', 'flags', 'identityStr']);
	if (unpacked != null && unpacked.identityStr) {
		this.convertIssued(unpacked);
		if (unpacked.issued != null) {
			this.convertFlags(unpacked);
			result = unpacked;
		}
	}
	return result;
};

// flags

AuthTokener.prototype.convertFlags = function (data) {
	if (data != null) {
		var flags = data.flags;
		if (flags) {
			this.ensureFlagToKey();
			for (var i = 0; i < flags.length; i++) {
				var flag = flags[i];
				var k = this.flagToKey[flag];
				if (k) {
					data[k] = true;
				}
			}
		}
		delete data.flags;
	}
};

AuthTokener.prototype.stringifyFlags = function (options) {
	var result = [];
	for (var k in options) {
		var flag = this.keyToFlag[k];
		if (flag && options[k]) {
			result.push(flag);
		}
	}
	return result.join('');
};

AuthTokener.prototype.keyToFlag = {
	isRenewal: 'r',
	useCookies: 'c',
	isSessionLifetime: 's',
	isLimited: 'l'
};

AuthTokener.prototype.ensureFlagToKey = function () {
	if (this.flagToKey == null) {
		var result = {};
		for (var k in this.keyToFlag) {
			result[this.keyToFlag[k]] = k;
		}
		this.flagToKey = result;
	}
};


module.exports = AuthTokener;
