"use strict";
var cookie = require('cookie');
var ops = require('ops');


var Tokener = function (signer, opt_options, opt_identityEqualsFunc, opt_getLastRevocationTimeFunc) {
	this.signer = signer;
	var authMaxAge = 60 * 60 * 24 * 7 * 2 * 1000; // 2 weeks in ms
	this.options = ops.cloneWithDefaults(opt_options, {
		maxAge: authMaxAge,
		postRevocationTrustDelay: 5 * 60 * 1000, // 5 minites in ms
		headers: {
			name: 'X-Auth',
			nameExpected: 'X-AuthExpected'
		},
		cookies: {
			name: 'auth',
			nameLimited: 'authTwin',
			useLimited: true, // use limited cookie CSRF protection (see README for details)
			forceNonHttp: false, // don't force exposing cookie data to JS
			secure: false,
			domain: null,
			path: '/'
		},
		renewal: {
			interval: Math.round(authMaxAge / 2),
			headers: {
				name: 'X-AuthRenewal',
				nameIssued: 'X-AuthRenewalIssued',
				nameMaxAge: 'X-AuthRenewalMaxAge'
			}
		}
	});
	this.identityEqualsFunc = opt_identityEqualsFunc;
	this.getLastRevocationTimeFunc = opt_getLastRevocationTimeFunc;

	this.options.headers.nameLower = this.options.headers.name.toLowerCase();
	this.options.headers.nameExpectedLower = this.options.headers.nameExpected.toLowerCase();
};

// API

// NOTE will not set auth cookies
// use loginWithCookies() if need them
Tokener.prototype.login = function (identity) {
	var tokenInfo = this.createToken(identity, true);
	return this.createTokenResult(tokenInfo);
};

Tokener.prototype.loginWithCookies = function (res, identity, isSessionLifetime) {
	var tokenInfo = this.createToken(identity, true, true, isSessionLifetime);
	this.setCookies(res, tokenInfo);
	return this.createTokenResult(tokenInfo, true);
};

Tokener.prototype.logoutWithCookies = function (res) {
	this.clearCookies(res);
};

Tokener.prototype.auth = function (token, opt_additionalToken, opt_expectedIdentity, opt_noCookiesMode) {
	var result = null;
	var data = this.parseToken(token, opt_additionalToken);
	if (data && !this.isRevoked(data)) {
		if (opt_expectedIdentity != null && !this.identityEquals(data.identity, opt_expectedIdentity)) {
			result = this.createUnexpectedIdentityResult(data, opt_expectedIdentity);
		}
		else {
			var renewalTokenInfo = null;
			// don't try to renew if got cookie token in no-cookies mode
			if (!(data.isCookie && opt_noCookiesMode)) {
				renewalTokenInfo = this.renew(data);
			}
			result = this.createAuthResult(data, renewalTokenInfo);
		}
	}
	return result;
};

Tokener.prototype.applyRenewal = function (res, renewal) {
	var names = this.options.renewal.headers;
	var renewalResult = renewal.result;
	if (renewalResult.token) {
		res.setHeader(names.name, renewalResult.token);
	}
	res.setHeader(names.nameIssued, renewalResult.issued.toISOString());
	res.setHeader(names.nameMaxAge, '' + renewalResult.maxAge);
	if (renewal.tokenInfo.isCookie) {
		this.setCookies(res, renewal.tokenInfo);
	}
};

Tokener.prototype.getAuthData = function (req, opt_allowCookieOnly) {
	var result = this.getHeaderBasedAuthData(req);
	if (result == null) {
		if (!this.options.cookies.useLimited) {
			result = this.getSingleCookieAuthData(req);
		}
		else if (opt_allowCookieOnly) {
			result = this.getCookieOnlyAuthData(req);
		}
	}
	return result;
};

Tokener.prototype.getAdditionalTokenFromCookie = function (req) {
	var result = null;
	if (req.cookies != null && this.options.cookies.useLimited) {
		result = req.cookies[this.options.cookies.name];
	}
	return result;
};

// internal stuff

Tokener.prototype.getHeaderBasedAuthData = function (req) {
	var result = null;
	var token = req.headers[this.options.headers.nameLower];
	if (token != null) {
		result = this.createAuthData(req, token, this.getAdditionalTokenFromCookie(req));
	}
	return result;
};

Tokener.prototype.getSingleCookieAuthData = function (req) {
	var result = null;
	if (req.cookies != null) {
		var token = req.cookies[this.options.cookies.name];
		if (token != null) {
			result = this.createAuthData(req, token);
		}
	}
	return result;
};

Tokener.prototype.getCookieOnlyAuthData = function (req) {
	var result = null;
	if (req.cookies != null) {
		// NOTE NOT getting full token directly
		// to fail if twin is not present
		// exactly like header-based auth will fail this case
		var token = req.cookies[this.options.cookies.nameLimited];
		var additionalToken = req.cookies[this.options.cookies.name];
		if (token != null && additionalToken != null) {
			result = this.createAuthData(req, token, additionalToken);
			result.cookieOnly = true;
		}
	}
	return result;
};

Tokener.prototype.createAuthData = function (req, token, opt_additionalToken) {
	var result = { token: token };
	var expectedIdentity = this.getExpectedIdentity(req);
	if (expectedIdentity != null) {
		result.expectedIdentity = expectedIdentity;
	}
	if (opt_additionalToken != null) {
		result.additionalToken = opt_additionalToken;
	}
	return result;
};

Tokener.prototype.createUnexpectedIdentityResult = function (token, renewalTokenInfo) {
	return { unexpectedIdentity: true };
};

Tokener.prototype.createAuthResult = function (token, renewalTokenInfo) {
	var result = { auth: token };
	if (renewalTokenInfo != null) {
		result.renewal = {
			result: this.createTokenResult(renewalTokenInfo, false, true),
			tokenInfo: renewalTokenInfo
		};
	}
	return result;
};

Tokener.prototype.getLastRevocationTime = function (token) {
	return this.getLastRevocationTimeFunc ? this.getLastRevocationTimeFunc(token) : null;
};

Tokener.prototype.isRevoked = function (token) {
	var lastRevocationTime = this.getLastRevocationTime(token);
	return lastRevocationTime != null &&
		(token.time <= lastRevocationTime ||
			// do not trust automatic renewals for a while to ensure
			// renewal was issued after all app instances was surely informed about revocation
			!token.isStrong && token.time <= lastRevocationTime + this.options.postRevocationTrustDelay);
};

Tokener.prototype.renew = function (token) {
	var result = null;
	if (token && !token.isLimited) {
		var renewalInterval = this.options.renewal.interval;
		if (renewalInterval != null && token.time + renewalInterval < Date.now()) {
			result = this.createToken(token.identity, false, token.isCookie, token.isSessionLifetime);
		}
	}
	return result;
};

Tokener.prototype.identityEquals = function (identityA, identityB) {
	var result;
	if (this.identityEqualsFunc != null) {
		result = this.identityEqualsFunc(identityA, identityB);
	}
	else {
		result = (identityA == identityB);
	}
	return result;
};

Tokener.prototype.createToken = function (identity, isStrong, isCookie, isSessionLifetime) {
	return this.createTokenInternal({
		identity: identity,
		time: Date.now(),
		isStrong: isStrong,
		isCookie: isCookie,
		isSessionLifetime: isSessionLifetime
	});
};

Tokener.prototype.createLimitedToken = function (tokenInfo) {
	return this.createTokenInternal({
		identity: tokenInfo.data.identity,
		time: tokenInfo.data.time,
		isLimited: true
	}).token;
};

Tokener.prototype.createTokenInternal = function (data) {
	return {
		data: data,
		token: this.signer.sign(this.packData(data))
	};
};

// TODO more compact format?
Tokener.prototype.packData = function (data) {
	var result = {
		identity: data.identity,
		time: data.time
	};
	if (data.isLimited) {
		result.limited = 1;
	}
	else {
		if (data.isStrong) {
			result.strong = 1;
		}
		if (data.isCookie) {
			result.cookie = 1;
			if (data.isSessionLifetime) {
				result.session = 1;
			}
		}
	}
	return new Buffer(JSON.stringify(result));
};

Tokener.prototype.unpackData = function (buffer) {
	var data = JSON.parse(buffer);
	var result = {
		identity: data.identity,
		time: data.time
	};
	if (data.limited) {
		result.isLimited = true;
	}
	else {
		if (data.strong) {
			result.isStrong = true;
		}
		if (data.cookie) {
			result.isCookie = true;
			if (data.session) {
				result.isSessionLifetime = true;
			}
		}
	}
	return result;
};

Tokener.prototype.createTokenResult = function (tokenInfo, opt_skipToken, opt_skipIdentity) {
	var issued = new Date(tokenInfo.data.time);
	issued.setUTCMilliseconds(0);
	var result = {
		issued: issued,
		maxAge: this.options.maxAge
	};
	if (!opt_skipToken) {
		result.token = tokenInfo.token;
	}
	if (!opt_skipIdentity) {
		result.identity = tokenInfo.data.identity;
	}
	return result;
};

Tokener.prototype.setCookie = function (res, name, value, expires, opt_isHttpOnly) {
	var cookieOptions = this.options.cookies;
	var options = {
		secure: cookieOptions.secure,
		httpOnly: !!opt_isHttpOnly && !cookieOptions.forceNonHttp,
		expires: expires,
		domain: cookieOptions.domain,
		path: cookieOptions.path
	};
	res.setHeader('Set-Cookie', cookie.serialize(name, value, options));
};

Tokener.prototype.setCookies = function (res, tokenInfo) {
	if (!tokenInfo.data.isCookie) {
		throw new Error('Cookie token expected');
	}
	var cookieOptions = this.options.cookies;
	var expires = (tokenInfo.data.isSessionLifetime ? null : new Date(tokenInfo.data.time + this.options.maxAge));
	this.setCookie(res, cookieOptions.name, tokenInfo.token, expires, true);
	if (cookieOptions.useLimited) {
		var limitedToken = this.createLimitedToken(tokenInfo);
		this.setCookie(res, cookieOptions.nameLimited, limitedToken, expires);
	}
};

Tokener.prototype.clearCookies = function (res) {
	var expires = new Date(0);
	var value = 'del';
	this.setCookie(res, this.options.cookies.name, value, expires);
	this.setCookie(res, this.options.cookies.nameLimited, value, expires);
};

Tokener.prototype.parseToken = function (token, opt_additionalToken) {
	var result = this.parseTokenInternal(token);
	if (result) {
		if (result.isLimited) {
			var limited = result;
			result = this.parseTokenInternal(opt_additionalToken);
			if (result && (result.isLimited || !this.identityEquals(limited.identity, result.identity))) {
				result = null;
			}
		}
	}
	return result;
};

Tokener.prototype.parseTokenInternal = function (token) {
	var result = null;
	if (token) {
		var buffer = this.signer.unsign(token);
		if (buffer) {
			var data = this.unpackData(buffer);
			if (data && data.time + this.options.maxAge >= Date.now()) {
				result = data;
			}
		}
	}
	return result;
};

Tokener.prototype.getExpectedIdentity = function (req) {
	var result = null;
	var expectedIdentityStr = req.headers[this.options.headers.nameExpectedLower];
	if (expectedIdentityStr) {
		try {
			result = JSON.parse(expectedIdentityStr);
		}
		catch (err) {
			// TODO throw an error instead to be able to respond 400 or something?
			result = null;
		}
	}
	return result;
};


module.exports = Tokener;
