"use strict";
var errh = require('ncbt').errh;
var ops = require('ops');
var AuthProblem = require('./auth_problem');


var AuthProvider = function (opt_options) {
	this.options = this.createOptions(opt_options);

	this.tokener = null;
	this.adapter = null;
	this.revoker = null;
};

AuthProvider.prototype.createOptions = function (opt_options) {
	return ops.cloneWithDefaults(opt_options, this.getDefaultOptions());
};

AuthProvider.prototype.getDefaultOptions = function () {
	var authMaxAge = 60 * 60 * 24 * 7 * 2 * 1000; // 2 weeks in ms
	return {
		maxAge: authMaxAge,
		useLimitedToken: true, // use limited token cookie CSRF protection (see README for details)
		renewalInterval: Math.round(authMaxAge / 2),

		allowedIssuedClockDeviation: 5 * 60 * 1000, // 5 minites in ms
	};
};

AuthProvider.prototype.setTokener = function (tokener) {
	this.tokener = tokener;
};

AuthProvider.prototype.setAdapter = function (adapter) {
	this.adapter = adapter;
};

AuthProvider.prototype.setRevoker = function (revoker) {
	this.revoker = revoker;
};

AuthProvider.prototype.login = function (res, identityStr, options, cb) {
	options = options || {};
	var useCookies = !!options.useCookies;
	var isSessionLifetime = !!options.isSessionLifetime;

	var self = this;
	this.tokener.createToken(identityStr, {
		useLimitedToken: this.options.useLimitedToken,
		useCookies: useCookies,
		isSessionLifetime: isSessionLifetime
	}, errh(function (tokenInfo) {
		if (res != null) {
			self.adapter.applyAuthData(res, tokenInfo, self.getMaxAge(isSessionLifetime), useCookies);
		}
		cb(null, {
			tokenInfo: tokenInfo,
			result: self.prepareTokenResult(tokenInfo)
		});
	}, cb));
};

AuthProvider.prototype.auth = function (req, res, options, cb) {
	var authData = this.adapter.extractAuthData(req);
	this.auth(authData, res, options, cb);
};

AuthProvider.prototype.authByData = function (authData, res, options, cb) {
	options = options || {};
	var allowUnprotected = !!options.allowUnprotected;
	// allowed values: null (auto), 'skip', 'force'
	var renewalMode = options.renewalMode || null;

	var self = this;
	var result = {
		authData: authData,
	};
	if (authData == null) {
		this.authProblem('NoAuthData', null, cb);
	}
	else if (!allowUnprotected && !authData.isCsrfProtected) {
		this.authProblem('CSRF', result, cb);
	}
	else {
		this.tokener.parseToken(authData.token, authData.additionalToken, errh(function (tokenData) {
			result.tokenData = tokenData;
			if (tokenData == null) {
				self.authProblem('InvalidToken', result, cb);
			}
			else if (!self.isValidIssued(tokenData)) {
				self.authProblem('InvalidIssued', result, cb);
			}
			else if (self.isExpired(tokenData)) {
				self.authProblem('Expired', result, cb);
			}
			else if (!self.isExpectedIdentity(tokenData, authData)) {
				self.authProblem('UnexpectedIdentity', result, cb);
			}
			else {
				self.checkRevoked(tokenData, errh(function (isRevoked) {
					if (isRevoked) {
						self.authProblem('Revoked', result, cb);
					}
					else if (renewalMode == 'force' || renewalMode != 'skip' && self.needRenew(tokenData)) {
						self.renew(res, tokenData, errh(function (renewalInfo) {
							result.renewalTokenInfo = renewalInfo.renewalTokenInfo;
							result.renewal = renewalInfo.renewal;
							cb(null, result);
						}, cb));
					}
					else {
						cb(null, result);
					}
				}, cb));
			}
		}, cb));
	}
};

AuthProvider.prototype.renew = function (res, tokenData, cb) {
	var self = this;
	this.tokener.renewToken(tokenData, self.options.useLimitedToken, errh(function (renewalTokenInfo) {
		if (res != null) {
			self.adapter.applyRenewal(res, renewalTokenInfo, self.getMaxAge(tokenData.isSessionLifetime), tokenData.useCookies);
		}
		cb(null, {
			renewalTokenInfo: renewalTokenInfo,
			renewal: self.prepareTokenResult(renewalTokenInfo, tokenData.isSessionLifetime)
		});
	}, cb));
};

AuthProvider.prototype.needRenew = function (tokenData) {
	// tokenData: as encoded to token by tokener
	return tokenData.issued + this.options.renewalInterval < Date.now();
};

AuthProvider.prototype.clearCookies = function (res) {
	this.adapter.clearCookies(res);
};

AuthProvider.prototype.isAuthProblem = function (err) {
	return err instanceof AuthProblem;
};

// internal

AuthProvider.prototype.authProblem = function (code, data, cb) {
	cb(new AuthProblem(code, data));
};

AuthProvider.prototype.prepareTokenResult = function (tokenInfo, opt_isSessionLifetime) {
	// tokenInfo: token, limitedToken, issued
	var isLimited = (tokenInfo.limitedToken != null);
	var result = {
		issued: tokenInfo.issued,
		token: isLimited ? tokenInfo.limitedToken : tokenInfo.token,
	};
	result.maxAge = this.getMaxAge();
	if (isLimited) {
		result.isLimited = true;
	}
	return result;
};

AuthProvider.prototype.getMaxAge = function (opt_isSessionLifetime) {
	return opt_isSessionLifetime ? null : this.options.maxAge;
};

AuthProvider.prototype.isValidIssued = function (tokenData) {
	return this.tokener.isValidIssued(tokenData.issued, this.options.allowedIssuedClockDeviation);
};

AuthProvider.prototype.isExpired = function (tokenData) {
	return this.tokener.isExpired(tokenData.issued, this.options.maxAge);
};

AuthProvider.prototype.isExpectedIdentity = function (tokenData, authData) {
	var result;
	if (authData.expectedIdentityStr == null) {
		result = true;
	}
	else {
		result = (tokenData.identityStr == authData.expectedIdentityStr);
	}
	return result;
};

AuthProvider.prototype.checkRevoked = function (tokenData, cb) {
	if (this.revoker != null) {
		this.revoker.checkRevoked(tokenData, cb);
	}
	else {
		cb(null, false);
	}
};


module.exports = AuthProvider;
