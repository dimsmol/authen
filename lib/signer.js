"use strict";
var crypto = require('crypto');
var urlSafeBase64 = require('./tools/url_safe_base64');
var constantTimeEquals = require('./tools/crypto').constantTimeEquals;


var Signer = function (options) {
	this.secrets = options.secrets;
	this.currentKey = options.currentKey; // NOTE must be alfanumeric
};

Signer.prototype.defaultAlgoName = 'sha1'; // NOTE cannot contain ':' char

Signer.prototype.isAllowedAlgo = function (algoName) {
	return this.algoName == this.defaultAlgo;
};

Signer.prototype.calcSignature = function (data, opt_algoName, opt_key) {
	var algoName = opt_algoName || this.defaultAlgoName;
	var key = opt_key || this.currentKey;
	var signature = this.calcSignatureRaw(data, algoName, this.secrets[key]);
	return {
		algoName: algoName,
		key: key,
		signature: signature
	};
};

Signer.prototype.calcSignatureRaw = function (data, algoName, secret) {
	var result = null;
	if (data && secret && this.isAllowedAlgo(algoName)) {
		result = urlSafeBase64.toUrlSafe(crypto.createHmac(algoName, secret).update(data).digest('base64'));
	}
	return result;
};

Signer.prototype.isValidSignature = function (signature, data, algoName, key) {
	var result = false;
	if (key) {
		result = this.isValidSignatureRaw(signature, data, algoName, this.secrets[key]);
	}
	return result;
};

Signer.prototype.isValidSignatureRaw = function (signature, data, algoName, secret) {
	var result = false;
	if (signature) {
		var calculatedSignature = this.calcSignatureRaw(data, algoName, secret);
		if (calculatedSignature) {
			result = constantTimeEquals(calculatedSignature, signature);
		}
	}
	return result;
};


module.exports = Signer;
