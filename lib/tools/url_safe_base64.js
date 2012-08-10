"use strict";
var UrlSafeBase64 = function () {
};

UrlSafeBase64.prototype.encode = function (buffer) {
	return this.toUrlSafe(buffer.toString('base64'));
};

UrlSafeBase64.prototype.decode = function (s) {
	return new Buffer(this.fromUrlSafe(s), 'base64');
};

UrlSafeBase64.prototype.toUrlSafe = function (s) {
	return s.replace(/\+/g, '-').replace(/\//g, '_');
};

UrlSafeBase64.prototype.fromUrlSafe = function (s) {
	return s.replace(/\-/g, '+').replace(/\_/g, '/');
};

var urlSafeBase64 = new UrlSafeBase64();
urlSafeBase64.UrlSafeBase64 = UrlSafeBase64;


module.exports = urlSafeBase64;
