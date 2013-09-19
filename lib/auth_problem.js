"use strict";
var mt = require('marked_types');


var AuthProblem = function (code, data) {
	this.code = code;
	this.data = data;
};
mt.mark(AuthProblem, 'authen:AuthProblem');


module.exports = AuthProblem;
