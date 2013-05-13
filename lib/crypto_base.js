"use strict";
var Checker = function (arr, v) {
	this.dict = this.createDict(arr);
	this.v = v;
};

Checker.prototype.check = function (v) {
	return this.v != null && v == this.v || this.dict != null && this.dict[v];
};

Checker.prototype.createDict = function (arr) {
	var result = null;
	if (arr != null && arr.length > 0) {
		result = {};
		for (var i = 0; i < arr.length; i++) {
			result[arr[i]] = true;
		}
	}
	return result;
};


var CryptoBase = function (options) {
	this.secrets = options.secrets;
	this.currentKey = options.currentKey;

	this.algo = options.algo || this.defaultAlgo;
	this.allowedAlgoChecker = this.createChecker(options.allowedAlgos, this.algo);
};

CryptoBase.prototype.createChecker = function (arr, v) {
	return new Checker(arr, v);
};

CryptoBase.prototype.isAllowedAlgo = function (algo) {
	return this.allowedAlgoChecker.check(algo);
};

CryptoBase.prototype.ensureBuffer = function (data, opt_encoding) {
	var result = null;
	if (data != null) {
		result = Buffer.isBuffer(data) ? data : new Buffer(data, opt_encoding);
	}
	return result;
};

CryptoBase.Checker = Checker;


module.exports = CryptoBase;
