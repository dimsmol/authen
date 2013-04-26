# authen

Features:

* Passwords hashing for storing them on server-side and validation against the hashes
* Signing data with secret
* Creation of auth tokens, validating them, handle renewal, expiration and revocation

Additional tools:

* Constant time equals for timing attacks prevention (tools/crypto)
* Url-safe base64 encoder/decoder (tools/url_safe_base64)

## Pwd

Password hashing tool.

* hash(pwd, cb)
* verify(pwd, hash, cb)

## Signer

Options:

* secrets - dict of secrets that can be used by signer
* currentKey - default key to get secret for signing

Methods:

* calcSignature(data, opt_algoName, opt_key) - calculates signature for data, using given algorythm and secret specified by given key. If algo name or key is not specified, defaults are used.

calcSignature returns null if algorythm is not supported or secret for given key is not found. In case of succesfull calculation it returns a dict with the following fields:

* signature - signature, url safe base64
* algoName - actually used algoName (guaranted to to the same as opt_algoName, if specified)
* key - actually used key (guaranted to to the same as opt_key, if specified)

## AuthProvider

Options:

* maxAge - max token age in ms, 2 weeks by default
* useLimitedToken - use limited token for CSRF protection (see "CSRF protection" below), true by default
* renewalInterval - how often renew token, 1 week by default
* allowedIssuedClockDeviation - ms, how far in future can be issue date of token to still treat it as valid (useful to deal with small server clocks deviations), 5 min by default

Initialization methods:

* setTokener(tokener) - sets token creator, usually Tokener instance, see below
* setAdapter(adapter) - sets auth data extractor and applier, usually HttpAdapter instance, see below
* setRevoker(revoker) - sets optional object providing tokens revocation info, usually Revoker subclass instance, see below

Initialization example:

```js
var provider = new AuthProvider();
provider.setTokener(new Tokener(new Signer({
	secrets: { a: 'my secret' },
	currentKey: 'a'
})));
provider.setAdapter(new HttpAdapter());
```

Methods:

* login(res, identityStr, options, cb) - creates auth tokens for given identity, applies auth to res if res is not null
	* options available:
		* useCookies - set auth cookies if res is not null
		* isSessionLifetime - make cookies session lifetime
	* returns dict with:
		* tokenInfo
			* token
			* limitedToken
			* issued - token timestamp
		* result - result ready to return to client
			* token
			* issued
			* maxAge
			* isLimited - true if token is limited, see "CSRF protection" below
* auth(req, res, options, cb) - extracts authentication data from request, creates renewal if need and applies it to res if it is not null
	* options available:
		* allowUnprotected - allows success even if not CSRF protected (useful for static files)
		* renewalMode - sets renewal mode:
			* null - auto, renew if it's time for it
			* 'skip' - do not renew
			* 'force' - renew
	* returns dict with:
		* authData - auth data extracted from req
		* tokenData - data extracted from token
		* renewalTokenInfo - token info used for renewal, structure is same as tokenInfo field returned by login()
		* renewal - renewal result ready to send to client, structure is same as result field returned by login()
	* can return AuthProblem object as an error, it's data field usually contains part of normal result, it's code field indicates type of problem:
			* NoAuthData - no auth data found
			* CSRF - CSRF protection required, but not found
			* InvalidToken - couldn't understand token
			* InvalidIssued - token's issued field is invalid (for example, too far in future)
			* Expired - token is expired
			* UnexpectedIdentity - token represents other identity than is expected, see "Expected Identity" below
			* Revoked - token is revoked
* authWithData(authData, res, options, cb) - same as auth, but requires extracted authData instead of req
* isAuthProblem(err) - checks if err is AuthProblem object
* clearCookies(res) - clears auth cookies

## CSRF protection

TODO

## Expected Identity

TODO

## Tokener

TODO

## HttpAdapter

TODO

## Revoker

TODO
