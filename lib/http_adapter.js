"use strict";
var cookie = require('cookie');
var ops = require('ops');


var HttpAdapter = function (opt_options) {
	var options = opt_options || {};
	this.cookieOptions = ops.cloneWithDefaults(options.cookie, this.getDefaultCookieOptions());

	var cookieNames = options.names && options.names.cookie;
	var headerNames = options.names && options.names.header;
	this.cookieNames = ops.cloneWithDefaults(cookieNames, this.getDefaultCookieNames());
	this.headerNames = ops.cloneWithDefaults(headerNames, this.getDefaultHeaderNames());

	this.headerNames.authLower = this.headerNames.auth.toLowerCase();
	this.headerNames.expectedLower = this.headerNames.expected.toLowerCase();
};

HttpAdapter.prototype.getDefaultCookieOptions = function () {
	return {
		httpOnly: true,
		secure: false,
		domain: null,
		path: '/'
	};
};

HttpAdapter.prototype.getDefaultCookieNames = function () {
	return {
		auth: 'auth',
		authLimited: 'authTwin'
	};
};

HttpAdapter.prototype.getDefaultHeaderNames = function () {
	return {
		auth: 'X-Auth',
		expected: 'X-AuthExpected',
		renewal: 'X-AuthRenewal',
		renewalIssued: 'X-AuthRenewalIssued',
		renewalMaxAge: 'X-AuthRenewalMaxAge'
	};
};

HttpAdapter.prototype.extractAuthData = function (req) {
	var token = this.getHeaderToken(req);
	var additionalToken = null;
	var isCsrfProtected = false;
	if (token != null) {
		isCsrfProtected = true;
		additionalToken = this.getCookieToken(req);
	}
	else {
		token = this.getCookieToken(req);
	}

	var expectedIdentityStr = null;
	if (token != null) {
		expectedIdentityStr = this.getExpectedIdentityStr(req);
	}

	return token == null ? null : {
		token: token,
		additionalToken: additionalToken,
		isCsrfProtected: isCsrfProtected,
		expectedIdentityStr: expectedIdentityStr
	};
};

HttpAdapter.prototype.applyAuthData = function (res, tokenInfo, maxAge, useCookies) {
	if (useCookies) {
		this.setTokenCookies(res, tokenInfo, maxAge);
	}
};

HttpAdapter.prototype.applyRenewal = function (res, renewalTokenInfo, maxAge, useCookies) {
	this.setRenewalHeaders(res, renewalTokenInfo, maxAge);
	this.applyAuthData(res, renewalTokenInfo, maxAge, useCookies);
};

HttpAdapter.prototype.clearCookies = function (res) {
	var expires = new Date(0);
	var value = 'del';
	this.setCookie(res, this.cookieNames.auth, value, expires);
	this.setCookie(res, this.cookieNames.authLimited, value, expires);
};

// internal

// extract

HttpAdapter.prototype.getHeaderToken = function (req) {
	return req.headers[this.headerNames.authLower];
};

HttpAdapter.prototype.getCookieToken = function (req) {
	return req.cookies != null ? req.cookies[this.cookieNames.auth] : null;
};

HttpAdapter.prototype.getExpectedIdentityStr = function (req) {
	var result = null;
	var expectedIdentityStr = req.headers[this.headerNames.expectedLower];
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

// apply

HttpAdapter.prototype.setTokenCookies = function (res, tokenInfo, maxAge) {
	var expires = (maxAge == null ? null : new Date(tokenInfo.issued + maxAge));
	this.setCookie(res, this.cookieNames.auth, tokenInfo.token, expires, true);
	if (tokenInfo.limitedToken != null) {
		this.setCookie(res, this.cookieNames.authLimited, tokenInfo.limitedToken, expires);
	}
};

HttpAdapter.prototype.setCookie = function (res, name, value, expires, opt_isHttpOnly) {
	var options = {
		secure: this.cookieOptions.secure,
		httpOnly: !!opt_isHttpOnly && this.cookieOptions.httpOnly,
		expires: expires,
		domain: this.cookieOptions.domain,
		path: this.cookieOptions.path
	};
	res.setHeader('Set-Cookie', cookie.serialize(name, value, options));
};

HttpAdapter.prototype.setRenewalHeaders = function (res, renewalTokenInfo, maxAge) {
	if (renewalTokenInfo.token != null) {
		res.setHeader(this.headerNames.renewal, renewalTokenInfo.token);
	}
	res.setHeader(this.headerNames.renewalIssued, renewalTokenInfo.issued.toISOString());
	if (maxAge != null) {
		res.setHeader(this.headerNames.renewalMaxAge, '' + maxAge);
	}
};


module.exports = HttpAdapter;
