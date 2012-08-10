"use strict";
var crypto = require('crypto');
var constantTimeEquals = require('./tools/crypto').constantTimeEquals;
var urlSafeBase64 = require('./tools/url_safe_base64');


var Signer = function (options) {
	this.options = options;
	// expected:
	// secrets - dict with available secrets
	// currentKey - key to choose secret
	// NOTE key cannot contain ':'
};

Signer.prototype.algoName = 'sha1'; // NOTE must be url safe, cannot contain ':'
Signer.prototype.separator = ':';

// produces algoName:key:encodedData:encodedSignature
// key is name of secret used to produce signature
Signer.prototype.sign = function (buffer) {
	// TODO add ability to encrypt
	// TODO add ability to compress data
	var encodedData = urlSafeBase64.encode(buffer);
	var signature = this.calcSignature(encodedData);

	var result = null;
	if (signature) {
		result = [this.algoName, this.options.currentKey, encodedData, signature].join(this.separator);
	}

	return result;
};

Signer.prototype.unsign = function (token) {
	try {
		return this.unsignInternal(token);
	}
	catch (err) {
	}
	return null;
};

Signer.prototype.unsignInternal = function (token) {
	var result = null;
	var parts = token.split(this.separator);
	var algoName = parts[0];
	var key = parts[1];
	var encodedData = parts[2];
	var signature = parts[3];

	if (algoName == this.algoName && signature) {
		var calculatedSignature = this.calcSignature(encodedData, key);
		if (constantTimeEquals(signature, calculatedSignature)) {
			result = urlSafeBase64.decode(encodedData);
		}
	}

	return result;
};

Signer.prototype.getSecret = function (opt_key) {
	var key = opt_key || this.options.currentKey;
	return this.options.secrets[key];
};

Signer.prototype.calcSignature = function (data, opt_key) {
	var secret = this.getSecret(opt_key);
	var result;
	if (secret) {
		result = urlSafeBase64.toUrlSafe(crypto.createHmac('sha1', secret).update(data).digest('base64'));
	}
	return result;
};


module.exports = Signer;
