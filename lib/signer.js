"use strict";
var crypto = require('crypto');
var urlSafeBase64 = require('./tools/url_safe_base64');


var Signer = function (options) {
	this.secrets = options.secrets;
	this.currentKey = options.currentKey; // NOTE must be alfanumeric
};

Signer.prototype.isSupportedAlgo = function (algoName) {
	return this.algoName == algoName;
};

Signer.prototype.getDefaultAlgoName = function () {
	return 'sha1'; // NOTE cannot contain ':' char
};

Signer.prototype.getDefaultKey = function () {
	return this.currentKey;
};

Signer.prototype.calcSignature = function (data, opt_algoName, opt_key) {
	var signature = null;
	var algoName = opt_algoName;
	var key = opt_key;
	if (!algoName || this.isSupportedAlgo(algoName)) {
		algoName = algoName || this.getDefaultAlgoName();
		key = key || this.getDefaultKey();
		var secret = this.secrets[key];
		if (secret) {
			signature = urlSafeBase64.toUrlSafe(crypto.createHmac(algoName, secret).update(data).digest('base64'));
		}
	}
	return {
		algoName: algoName,
		key: key,
		signature: signature
	};
};


module.exports = Signer;
