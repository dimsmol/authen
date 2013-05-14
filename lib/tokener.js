"use strict";
var Tokener = function () {
	this.signer = null;
	this.crypter = null;
	this.algoMaps = null;
};

Tokener.prototype.separator = ':';

// api

Tokener.prototype.setSigner = function (signer) {
	this.signer = signer;
};

Tokener.prototype.setCrypter = function (crypter) {
	this.crypter = crypter;
};

Tokener.prototype.setAlgoMaps = function (maps) {
	this.algoMaps = maps;
};

Tokener.prototype.createToken = function (data, opt_prefix) {
	data = this.packData(data);
	return this.createTokenByPacked(data, opt_prefix);
};

Tokener.prototype.parseToken = function (token) {
	var data = this.parseTokenToPacked(token);
	return this.unpackData(data);
};

// api - issued

Tokener.prototype.isValidIssued = function (issued, opt_allowedIssuedClockDeviation) {
	var result = false;
	if (issued && issued.constructor === Number) {
		var allowedIssuedClockDeviation = opt_allowedIssuedClockDeviation || 0;
		// allow issued to be a little in future
		// to handle possible server clocks deviations
		result = (issued - allowedIssuedClockDeviation <= Date.now());
	}
	return result;
};

Tokener.prototype.isExpired = function (issued, maxAge) {
	var result = true;
	if (maxAge) {
		result = (issued + maxAge < Date.now());
	}
	return result;
};

// internal

// NOTE prefix must not contain separator
Tokener.prototype.createTokenByPacked = function (data, opt_prefix) {
	var isSigned = false;
	var info;
	if (this.crypter != null) {
		info = this.crypter.encrypt(data);
		data = this.packCryptInfo(info);
		isSigned = info.isSigned;
	}
	if (!isSigned && this.signer != null) {
		info = this.signer.calcSignature(data);
		info.data = data;
		data = this.packSignInfo(info);
		isSigned = true;
	}
	// must be at least signed
	return isSigned ? this.packToken(data, opt_prefix) : null;
};

Tokener.prototype.parseTokenToPacked = function (token) {
	var data = this.unpackToken(token);
	var isSigned = false;
	if (data) {
		var info;
		if (this.signer != null) {
			info = this.unpackSignInfo(data);
			if (info != null) {
				var isOk = this.signer.isValidSignature(info.signature, info.data, info.algo, info.key);
				data = (isOk ? info.data : null);
				isSigned = true;
			}
		}
		if (data && this.crypter != null) {
			info = this.unpackCryptInfo(data);
			if (info != null) {
				isSigned = isSigned || this.crypter.isSigningAlgo(info.algo);
				if (isSigned) {
					data = this.crypter.decrypt(info.data, info.algo, info.key);
				}
			}
		}
	}
	// must be at least signed
	return isSigned ? data : null;
};

// data

Tokener.prototype.packData = function (data) {
	// NOTE always use '' prefix to distinguish from signed/crypted data
	return this.pack(['', this.getIssuedStr(), data]);
};

Tokener.prototype.unpackData = function (data) {
	var result = this.unpack(this.ensureString(data), '', ['issued', 'data']);
	if (result != null) {
		this.convertIssued(result);
	}
	return result;
};

// crypt

Tokener.prototype.packCryptInfo = function (info) {
	return this.pack(['c', this.mapAlgo(info.algo, 'crypter'), info.key, info.data.toString('base64')]);
};

Tokener.prototype.unpackCryptInfo = function (data) {
	var result = this.unpack(data, 'c', ['algo', 'key', 'data']);
	this.convertAlgo(result, 'crypter');
	return result;
};

// sign

Tokener.prototype.packSignInfo = function (info) {
	return this.pack(['s', this.mapAlgo(info.algo, 'signer'), info.key, info.signature.toString('base64'), info.data]);
};

Tokener.prototype.unpackSignInfo = function (data) {
	var result = this.unpack(data, 's', ['algo', 'key', 'signature', 'data']);
	this.convertAlgo(result, 'signer');
	return result;
};

// token

Tokener.prototype.packToken = function (data, opt_prefix) {
	var prefix = opt_prefix || '';
	return this.pack([prefix, data]);
};

Tokener.prototype.unpackToken = function (data) {
	return this.unpack(data, true);
};

// utility

Tokener.prototype.pack = function (arr) {
	return arr.join(this.separator);
};

Tokener.prototype.unpack = function (data, prefix, names, opt_separator) {
	// prefix:
	// - use `null` for no prefix
	// - use `true` for any prefix
	var result = null;
	if (data) {
		var separator = opt_separator || this.separator;
		var isValid = true;
		var l = separator.length;
		var pos = 0;
		if (prefix != null) {
			var sepIdx = data.indexOf(separator);
			// here indexOf() can be replaced with startsWith() when it will be supported by node.js
			isValid = (prefix === true && sepIdx >= 0 || sepIdx == prefix.length && data.indexOf(prefix) === 0);
			pos = sepIdx + l;
		}
		if (isValid) {
			if (names == null) {
				result = data.substring(pos);
			}
			else {
				result = {};
				var lastNameIdx = names.length - 1;
				for (var i = 0; i <= lastNameIdx; i++) {
					var idx = (i == lastNameIdx ? undefined : data.indexOf(separator, pos));
					if (idx < 0) {
						break;
					}
					var v = data.substring(pos, idx);
					var name = names[i];
					if (name != null) {
						result[name] = v;
					}
					pos = idx + l;
				}
			}
		}
	}
	return result;
};

// buffer

Tokener.prototype.convertToBuffer = function (data, k, opt_encoding) {
	if (data != null) {
		data[k] = new Buffer(data[k], opt_encoding);
	}
};

Tokener.prototype.ensureString = function (data, opt_encoding) {
	return Buffer.isBuffer(data) ? data.toString(opt_encoding) : data;
};

// issued

Tokener.prototype.getIssuedStr = function () {
	return this.stringifyIssued(this.getIssued());
};

Tokener.prototype.getIssued = function () {
	return Date.now();
};

Tokener.prototype.convertIssued = function (data) {
	if (data != null) {
		data.issued = this.parseIssued(data.issued);
	}
};

Tokener.prototype.stringifyIssued = function (v) {
	return v.toString(16);
};

Tokener.prototype.parseIssued = function (v) {
	var result = null;
	if (v) {
		result = parseInt(v, 16);
		if (isNaN(result)) {
			result = null;
		}
	}
	return result;
};

// algoMaps

Tokener.prototype.mapAlgo = function (algo, k) {
	var result = algo;
	if (this.algoMaps != null) {
		var map = this.algoMaps[k];
		if (map != null) {
			result = map[algo];
			if (result == null) {
				result = this.getMissedAlgoMapping(algo, k);
			}
		}
	}
	return result;
};

Tokener.prototype.getMissedAlgoMapping = function (algo, k) {
	throw new Error(['Missed algo mapping for ', k, ' algorythm ', algo].join(''));
};

Tokener.prototype.convertAlgo = function (data, k) {
	if (data != null && this.algoMaps != null) {
		var algo = data.algo;
		var map = this.algoMaps[k];
		if (algo != null && map != null) {
			data.algo = null;
			for (var mapKey in map) {
				if (map[mapKey] == algo) {
					data.algo = mapKey;
				}
			}
		}
	}
};

// static

Tokener.getPrefix = function (token, opt_separator) {
	var result = null;
	if (token) {
		var separator = opt_separator || Tokener.prototype.separator;
		var sepIdx = token.indexOf(separator);
		if (sepIdx >= 0) {
			result = token.substring(0, sepIdx);
		}
	}
	return result;
};


module.exports = Tokener;
