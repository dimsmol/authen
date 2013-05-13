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
	if (data != null && secret && this.isAllowedAlgo(algo)) {
		var cipher = crypto.createCipher(algo, secret);
		result = this.crypt(cipher, this.ensureBuffer(data));
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
	if (encryptedData != null && secret && this.isAllowedAlgo(algo)) {
		var decipher = crypto.createDecipher(algo, secret);
		result = this.crypt(decipher, this.ensureBuffer(encryptedData, 'base64'));
	}
	return result;
};

Crypter.prototype.crypt = function (actor, data) {
	return Buffer.concat([
		// old node.js workaround
		this.ensureBuffer(actor.update(data), 'binary'),
		this.ensureBuffer(actor.final(), 'binary')
	]);
};


module.exports = Crypter;
