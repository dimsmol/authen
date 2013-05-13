"use strict";
var inherits = require('util').inherits;
var crypto = require('crypto');
var CryptoBase = require('./crypto_base');


var Crypter = function (options) {
	CryptoBase.call(this, options);
	this.signingAlgoChecker = this.createChecker(options.signingAlgos);
};
inherits(Crypter, CryptoBase);

Crypter.prototype.defaultAlgo = 'aes256';

Crypter.prototype.isSigningAlgo = function (algo) {
	return this.signingAlgoChecker.check(algo);
};

Crypter.prototype.encrypt = function (data, opt_algo, opt_key) {
	var algo = opt_algo || this.defaultAlgo;
	var key = opt_key || this.currentKey;
	var encryptedData = this.encryptRaw(data, algo, this.secrets[key]);
	return {
		algo: algo,
		key: key,
		isSigned: this.isSigningAlgo(algo),
		data: encryptedData
	};
};

Crypter.prototype.encryptRaw = function (data, algo, secret) {
	var result = null;
	if (data && secret && this.isAllowedAlgo(algo)) {
		var cipher = crypto.createCipher(algo, secret);
		result = cipher.update(data, 'utf8', 'base64') + cipher.final('base64');
	}
	return result;
};

Crypter.prototype.decrypt = function (encryptedData, algo, key) {
	var result = null;
	if (key) {
		result = this.decryptRaw(encryptedData, algo, this.secrets[key]);
	}
	return result;
};

Crypter.prototype.decryptRaw = function (encryptedData, algo, secret) {
	var result = null;
	if (encryptedData && secret && this.isAllowedAlgo(algo)) {
		var decipher = crypto.createDecipher(algo, secret);
		result = decipher.update(encryptedData, 'base64', 'utf8') + decipher.final('utf8');
	}
	return result;
};


module.exports = Crypter;
