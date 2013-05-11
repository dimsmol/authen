"use strict";
var crypto = require('crypto');
var constantTimeEquals = require('./tools/crypto').constantTimeEquals;


var Signer = function (options) {
	this.secrets = options.secrets;
	this.currentKey = options.currentKey;
};

Signer.prototype.defaultAlgo = 'sha1';

Signer.prototype.isAllowedAlgo = function (algo) {
	return algo == this.defaultAlgo;
};

Signer.prototype.calcSignature = function (data, opt_algo, opt_key) {
	var algo = opt_algo || this.defaultAlgo;
	var key = opt_key || this.currentKey;
	var signature = this.calcSignatureRaw(data, algo, this.secrets[key]);
	return {
		algo: algo,
		key: key,
		signature: signature
	};
};

Signer.prototype.calcSignatureRaw = function (data, algo, secret) {
	var result = null;
	if (data && secret && this.isAllowedAlgo(algo)) {
		result = crypto.createHmac(algo, secret).update(data).digest('base64');
	}
	return result;
};

Signer.prototype.isValidSignature = function (signature, data, algo, key) {
	var result = false;
	if (key) {
		result = this.isValidSignatureRaw(signature, data, algo, this.secrets[key]);
	}
	return result;
};

Signer.prototype.isValidSignatureRaw = function (signature, data, algo, secret) {
	var result = false;
	if (signature) {
		var calculatedSignature = this.calcSignatureRaw(data, algo, secret);
		if (calculatedSignature) {
			result = constantTimeEquals(calculatedSignature, signature);
		}
	}
	return result;
};


module.exports = Signer;
