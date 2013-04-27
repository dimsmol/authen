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

Signs data using specified secret provided by dictionary of secrets.

Options:

* secrets - dict of secrets that can be used by signer
* currentKey - default key to get secret for signing

Methods:

* calcSignature(data, opt_algoName, opt_key) - calculates signature for data, using given algorythm and secret specified by given key. If algo name or key is not specified, defaults are used.
	* returns a dict with the following fields:
		* signature - signature, as returned by calcSignatureRaw
		* algoName - actually used algoName (guaranted to to the same as opt_algoName, if specified)
		* key - actually used key (guaranted to to the same as opt_key, if specified)
* calcSignatureRaw(data, algoName, secret) - internally used by calcSignature
	* returns null if data or secret is empty or algorythm is not allowed (the only allowed algo is 'sha1')
	* otherwise returns signature, url safe base64 string
* isValidSignature(signature, data, algoName, key) - returns true if signature is valid for given parameters
* isValidSignatureRaw(signature, data, algoName, secret) - internally used by isValidSignature

## AuthProvider

Provides login and authentication features.

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
			* Note, that result doesn't contain identity, because AuthProvider knows only it's string representation. So, you need to add it yourself. Also it could be useful sometimes to include identityStr into result as well, to use it as expected identity.
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
* authByData(authData, res, options, cb) - same as auth(), but requires extracted authData instead of req, used by auth()
* renew(res, tokenData, cb) - creates renewal and applies it to res if it is not null, used by authByData()
* needRenew(tokenData) - checks if token needs renewal, used by authByData()
* isAuthProblem(err) - checks if err is AuthProblem object
* clearCookies(res) - clears auth cookies

## Tokener

Creates and parses tokens.

Number of Tokener methods made asynchronous to allow session-based token classes keeping the same interface.

Constructor:

* Tokener(signer, opt_options)
	* signer - usually instance of Signer
	* options available:
		* prefix - prefix to be used for token, useful for separating different kinds of tokens, token versioning or whatever, empty string by default

Methods:

* createToken(identityStr, options, cb) - creates a token for identityStr
	* options:
		* isRenewal - must be true if token was created as a renewal
		* useCookies - must be true if initial login was performed with use of cookies (need to know for renewals)
		* isSessionLifetime - must be true if initial login was session lifetime (need to know for renewals)
		* useLimitedToken - must be true to use limited token for CSRF protection
	* returns a dict:
		* token
		* limitedToken
		* issued - timestamp
* renewToken(tokenData, useLimitedToken, cb) - creates renewal token by given token data
	* tokenData must contain:
		* identityStr
		* useLimitedToken
		* useCookies
		* isSessionLifetime
	* returns the same as createToken()
* extractTokenData(token, additionalToken, cb) - extracts token data checking signature and handling additional token
	* returns a dict:
		* identityStr
		* issued
		* isRenewal
		* useCookies
		* isSessionLifetime

## HttpAdapter

Extracts auth data from HTTP request and applies them to response.

Options:

* cookie
	* httpOnly - use http only cookie, true by default
	* secure - use secure cookies, false by default
	* domain - domain for cookies, null (not specified) by default
	* path - path for cookies, '/' by default
* names
	* cookie
		* auth - auth cookie name, 'auth' by default
		* authLimited - limited auth cookie name, 'authTwin' by default
	* header
		* auth - auth header name (request), 'X-Auth' by default
		* expected - expected identity header name (request), 'X-AuthExpected' by default
		* renewal - renewal token headername (response), 'X-AuthRenewal' by default
		* renewalIssued - renewal issued timestamp header name (response), 'X-AuthRenewalIssued' by default
		* renewalMaxAge - renewal max age header name (response), 'X-AuthRenewalMaxAge' by default

Methods:

* extractAuthData(req) - extracts auth data from request
	* returns a dict:
		* token
		* additionalToken
		* isCsrfProtected - true if request is CSRF protected
		* expectedIdentityStr
* applyAuthData(res, tokenInfo, maxAge, useCookies) - applies auth data to response
	* tokenInfo is a dict:
		* token
		* limitedToken
		* issued
	* maxAge is used for cookies only
* applyRenewal(res, renewalTokenInfo, maxAge, useCookies) - the same as applyAuthData(), but for renewals
* clearCookies(res) - clears auth cookies

## Revoker

Provides info about token revocation. This is an abstract class representing "last revocation time" based revocation - all tokens issued before given time moment are treated as revoked. You must override getLastRevokationTime() method to get working implementation.

Options:

* postRevocationTrustDelay - specifies a period after revocation in ms for which all renewal tokens will be treated as revoked, 5 min by default. This allows to prevent keep previously got token active by continuously renewing it. Period must be long enough to allow all the servers share info about latest "last revokation time" update.

Methods:

* checkRevoked(tokenData, cb) - checks if given token is revoked
	* returns true if token is revoked
* getLastRevokationTime(cb) - abstract method you must implement
	* returns last revokation time timestamp

## CSRF protection

CSRF is a problem closely related to cookies. So it's applied if you use cookies for authentication.

Auth cookie itself is not enough to ensure request is initiated by user or by trusted web application. So, AuthProvider requires auth token to be added to request HTTP header as well to ensure request is CSRF protected.

_Note, that it couldn't be done for static requests, so they cannot be CSRF protected._

But auth cookie is often "http only", so JS code have no access to auth token. To solve this problem, AuthProvider allows to generate pair of tokens - normal and limited one. This way normal token will be stored in auth cookie and limited one will be stored in other cookie and also returned to client. Client then can use limited cookie to add it to request header. Limited token is itself not enough for authentication and after getting it AuthProvider will try to get normal token from auth cookie. If both tokens match each other, normal token will be used for authentication.

Note, that useLimitedToken option of AuthProvider is useful only for "http only" cookies, or else you can use normal auth token from cookie to copy it to HTTP header. And vice versa, if "http only" cookie is used, there is no sense to disable useLimitedToken, because this way result sent to client will contain normal token and JS will have access to it (which we tried to prevent using "http only" cookie).

And again, all this stuff is useful only for authentication using cookies, sending auth token in HTTP header is CSRF protected without any additional tricks.

## Expected Identity

If user authenticated in one browser tab reauthenticates in other, first one will send requests with new auth cookies without even knowing it. So it can end up with mixed data - some loaded with old authentication and some with new one.

To prevent such a mess, you can add expected identity known to your application to HTTP header (usuall X-AuthExpected). If expected identity is provided, AuthProvider will check that your auth token is expected one.
