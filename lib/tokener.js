"use strict";
var constantTimeEquals = require('./tools/crypto').constantTimeEquals;


var Tokener = function (signer) {
	this.signer = signer;

	this.flagToKey = null;
};

Tokener.prototype.separator = ':';
Tokener.prototype.dataSeparator = ':';

Tokener.prototype.createToken = function (identityStr, options, cb) {
	// options available:
	// isRenewal, useCookies, isSessionLifetime, useLimitedToken
	options = options || {};
	var issued = Date.now();
	var tokenData = {
		identityStr: identityStr,
		issued: issued,
		isRenewal: options.isRenewal,
		useCookies: options.useCookies,
		isSessionLifetime: options.isSessionLifetime
	};
	var token = this.encode(tokenData);
	var limitedToken = null;
	if (options.useCookies && options.useLimitedToken) {
		limitedToken = this.encode({
			identityStr: identityStr,
			issued: issued,
			isLimited: true
		});
	}
	cb(null, {
		token: token,
		limitedToken: limitedToken,
		issued: issued
	});
};

Tokener.prototype.renewToken = function (tokenData, useLimitedToken, cb) {
	// tokenData - as encoded to token by createToken
	this.createToken(tokenData.identityStr, {
		isRenewal: true,
		useLimitedToken: useLimitedToken,
		useCookies: tokenData.useCookies,
		isSessionLifetime: tokenData.isSessionLifetime
	}, cb);
};

Tokener.prototype.extractTokenData = function (token, additionalToken, cb) {
	var tokenData = this.extractSingleTokenData(token);
	if (tokenData != null && tokenData.isLimited) {
		var limitedTokenData = tokenData;
		tokenData = this.extractSingleTokenData(additionalToken);
		if (tokenData.issued != limitedTokenData.issued || tokenData.identityStr != additionalToken.identityStr) {
			tokenData = null;
		}
	}
	cb(null, tokenData);
};

// internal

Tokener.prototype.extractSingleTokenData = function (token) {
	var result = null;
	if (token != null) {
		var parts = this.unpackToken(token);
		if (this.isSignatureCorrect(parts.signature, parts.tokenDataStr, parts.algoName, parts.key)) {
			result = this.parse(parts.tokenDataStr);
		}
	}
	return result;
};

Tokener.prototype.isSignatureCorrect = function (signature, tokenDataStr, algoName, key) {
	var result = false;
	if (signature && tokenDataStr && algoName && key) {
		var signatureInfo = this.signer.calcSignature(tokenDataStr, algoName, key);
		result = (signatureInfo.signature && constantTimeEquals(signatureInfo.signature, signature));
	}
	return result;
};

Tokener.prototype.encode = function (tokenData) {
	var str = this.stringify(tokenData);
	var signatureInfo = this.signer.calcSignature(str);
	return this.packToToken(str, signatureInfo);
};

Tokener.prototype.packToToken = function (tokenDataStr, signatureInfo) {
	return [
		signatureInfo.algoName,
		signatureInfo.key,
		signatureInfo.signature,
		tokenDataStr
	].join(this.separator);
};

Tokener.prototype.unpackToken = function (token) {
	return this.extractParts(token, [
		'algoName', 'key', 'signature', 'tokenDataStr'
	], this.separator);
};

Tokener.prototype.stringify = function (tokenData) {
	var flags = this.createFlags(tokenData);
	return [
		flags.join(''),
		tokenData.issued.toString(16),
		tokenData.identityStr
	].join(this.dataSeparator);
};

Tokener.prototype.parse = function (tokenDataStr) {
	var parts = this.extractParts(tokenDataStr, [
		'flags', 'issued', 'identityStr'
	], this.dataSeparator);
	var result = {
		identityStr: parts.identityStr,
		issued: parseInt(parts.issued, 16)
	};
	this.parseFlags(parts.flags, result);
	return result;
};

Tokener.prototype.keyToFlag = {
	isRenewal: 'r',
	useCookies: 'c',
	isSessionLifetime: 's',
	isLimited: 'l'
};

Tokener.prototype.ensureFlagToKey = function () {
	if (this.flagToKey == null) {
		var result = {};
		for (var k in this.keyToFlag) {
			result[this.keyToFlag[k]] = k;
		}
		this.flagToKey = result;
	}
};

Tokener.prototype.createFlags = function (tokenData) {
	var result = [];
	this.ensureFlagToKey();
	for (var k in tokenData) {
		var flag = this.keyToFlag[k];
		if (flag && tokenData[k]) {
			result.push(flag);
		}
	}
	return result.join('');
};

Tokener.prototype.parseFlags = function (flags, tokenData) {
	for (var i = 0; i < flags.length; i++) {
		var flag = flags[i];
		var k = this.flagToKey[flag];
		if (k) {
			tokenData[k] = true;
		}
	}
};

Tokener.prototype.extractParts = function (str, names, separator) {
	var result = {};
	var l = separator.length;
	var lastNameIdx = names.length - 1;
	var pos = 0;
	for (var i = 0; i <= lastNameIdx; i++) {
		var name = names[i];
		var idx;
		if (i < lastNameIdx) {
			idx = str.indexOf(separator, pos);
		}
		result[name] = str.substring(pos, idx);
		pos = idx + l;
	}
	return result;
};


module.exports = Tokener;
