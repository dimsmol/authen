"use strict";
var crypto = require('crypto');
var async = require('async');
var errh = require('ncbt').errh;
var ops = require('ops');
var constantTimeEquals = require('./tools/crypto').constantTimeEquals;


var Pwd = function (opt_options) {
	this.options = ops.applyDefaults(opt_options, {
		len: 128,
		iterations: 12000,
		saltLen: 32
	});
};

Pwd.prototype.algoName = 'pbkdf2_sha1';

Pwd.prototype.hash = function (pwd, cb) {
	var self = this;
	this.hashInternal(pwd, errh(function (hash, salt, cb) {
		cb(null, [
			self.algoName,
			self.options.iterations,
			self.options.len,
			salt,
			new Buffer(hash, 'binary').toString('base64')
		].join('$'));
	}, cb));
};

Pwd.prototype.verify = function (pwd, hash, cb) {
	var self = this;
	var parts = hash.split('$');
	var algoName = parts[0];
	var iterations = parseInt(parts[1], 10);
	var len = parseInt(parts[2], 10);
	var salt = parts[3];
	var base64Hash = parts[4];
	if (!algoName || isNaN(iterations) || isNaN(len) || !salt || !base64Hash) {
		cb(new Error('Invalid hash value'));
	}
	else if (algoName != this.algoName) {
		cb(new Error('Algorythm is not supported: ' + algoName));
	}
	else {
		this.verifyInternal(pwd, new Buffer(base64Hash, 'base64'), salt, iterations, len, cb);
	}
};

Pwd.prototype.hashInternal = function (pwd, cb) {
	var self = this;
	var salt;
	async.waterfall([
		function (cb) {
			self.createSalt(cb);
		},
		function (createdSalt, cb) {
			salt = createdSalt;
			crypto.pbkdf2(pwd, salt, self.options.iterations, self.options.len, cb);
		},
		function (hash, cb) {
			cb(null, hash, salt);
		}
	], cb);
};

Pwd.prototype.verifyInternal = function (pwd, hash, salt, iterations, len, cb) {
	var self = this;
	crypto.pbkdf2(pwd, salt, iterations, len, errh(function(calculatedHash, cb){
		cb(null, constantTimeEquals(hash, new Buffer(calculatedHash, 'binary')));
	}, cb));
};

Pwd.prototype.createSalt = function (cb) {
	crypto.randomBytes(this.options.saltLen, errh(function (salt, cb) {
		cb(null, salt.toString('base64'));
	}, cb));
};


module.exports = Pwd;
