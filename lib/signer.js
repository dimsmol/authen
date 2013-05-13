"use strict";
var inherits = require('util').inherits;
var crypto = require('crypto');
var constantTimeEquals = require('./tools/crypto').constantTimeEquals;
var CryptoBase = require('./crypto_base');


var Signer = function (options) {
	CryptoBase.call(this, options);
};
inherits(Signer, CryptoBase);

Signer.prototype.defaultAlgo = 'sha1';

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
	if (data != null && secret && this.isAllowedAlgo(algo)) {
		result = crypto.createHmac(algo, secret).update(this.ensureBuffer(data)).digest();
		result = this.ensureBuffer(result, 'binary'); // old node.js workaround
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
	if (signature != null && signature.length > 0) {
		var calculatedSignature = this.calcSignatureRaw(data, algo, secret);
		if (calculatedSignature != null) {
			result = constantTimeEquals(calculatedSignature, this.ensureBuffer(signature, 'base64'));
		}
	}
	return result;
};


module.exports = Signer;
