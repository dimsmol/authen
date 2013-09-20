# authen

Features:

* Passwords hashing for storing them on server-side and validation against the hashes
* Signing data with secret
* Encrypting and decrypting data with secret
* Creation of simple tokens - signed or both encrypted and signed
* Creation of auth tokens, validating them, handle renewal, expiration and revocation

If you are planning to use encryption, see "Notes on Encryption" to avoid possible pitfalls.

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

* algo - optional, default algorythm to use, 'sha1' will be used if not specified
* allowedAlgos - optional, list of allowed algos (in addition to algo)
* secrets - dict of secrets that can be used by signer
* currentKey - default key to get secret for signing

Methods:

* calcSignature(data, opt_algo, opt_key) - calculates signature for data, using given algorythm and secret specified by given key
	* arguments
		* data can be string or Buffer
		* algo from options will be used if opt_algo is missed
		* currentKey from options will be used if opt_key is missed
	* returns a dict with the following fields:
		* signature - signature, as returned by calcSignatureRaw
		* algoName - actually used algoName (guaranted to to the same as opt_algoName, if specified)
		* key - actually used key (guaranted to to the same as opt_key, if specified)
* calcSignatureRaw(data, algoName, secret) - internally used by calcSignature
	* returns null if data or secret is empty or algorythm is not allowed
	* otherwise returns signature (a Buffer object)
* isValidSignature(signature, data, algoName, key) - returns true if signature is valid for given parameters
	* signature can be base64 string or Buffer
* isValidSignatureRaw(signature, data, algoName, secret) - internally used by isValidSignature

## Crypter

Encrypts and decrypts data using specified secret provided by dictionary of secrets.

Options:

* algo - optional, default algorythm to use, 'aes256' if not specified
* allowedAlgos - optional, list of allowed algos (in addition to algo)
* signingAlgos - optional, list of algos that includes signing in addition to encryption, dangerous, use only if you know what you're doing
* secrets - dict of secrets that can be used by signer
* currentKey - default key to get secret for signing

Methods:

* encrypt(data, opt_algo, opt_key) - encrypts data, using given algorythm and secret specified by given key
	* arguments
		* data can be utf8 string or Buffer
		* algo from options will be used if opt_algo is missed
		* currentKey from options will be used if opt_key is missed
	* returns a dict with the following fields:
		* data - encrypted data, as returned by encryptRaw
		* algoName - actually used algoName (guaranted to to the same as opt_algoName, if specified)
		* key - actually used key (guaranted to to the same as opt_key, if specified)
* encryptRaw(data, algoName, secret) - internally used by encrypt()
	* returns null if data or secret is empty or algorythm is not allowed
	* otherwise returns encrypted data (a Buffer object)
* decrypt(data, algoName, key) - decrypts data
	* data can be base64 string or Buffer
* decryptRaw(data, algoName, secret) - internally used by decrypt()

## AuthProvider

Provides login and authentication features.

Options:

* maxAge - max token age in ms, 2 weeks by default
* useLimitedToken - use limited token for CSRF protection (see "CSRF protection" below), true by default
* renewalInterval - how often renew token, 1 week by default
* allowedIssuedClockDeviation - ms, how far in future can be issue date of token to still treat it as valid (useful to deal with small server clocks deviations), 5 min by default

Initialization methods and properties:

* type - string, can be used to identify provider if multiple are used
* setTokener(tokener) - sets token creator, usually AuthTokener instance, see below
	* don't use Tokener instance instead of AuthTokener, it lacks number of methods required by AuthProvider
* setAdapter(adapter) - sets auth data extractor and applier, usually HttpAdapter instance, see below
* setRevoker(revoker) - sets optional object providing tokens revocation info, usually Revoker subclass instance, see below

Initialization example:

```js
var tokener = new AuthTokener();
tokener.setSigner(new Signer({
	secrets: { a: 'my secret' },
	currentKey: 'a'
}));

var provider = new AuthProvider();
provider.setTokener(tokener);
provider.setAdapter(new HttpAdapter());
```

Methods:

* login(res, identity, options, cb) - creates auth tokens for given identity, applies auth to res if res is not null
	* options available:
		* useCookies - set auth cookies if res is not null
		* isSessionLifetime - make cookies session lifetime
	* returns dict with:
		* tokenInfo
			* token
			* limitedToken
			* issued - token timestamp
		* identityStr - string representation of identity
		* result - result ready to return to client
			* token
			* issued
			* maxAge
			* isLimited - true if token is limited, see "CSRF protection" below
			* Note that identity and identityStr are not included to result, because it isn't always useful. If you need one of them or both, please include them yourself.
* auth(req, res, options, cb) - extracts authentication data from request, creates renewal if need and applies it to res if it is not null
	* options available:
		* allowUnprotected - allows success even if not CSRF protected (useful for static files)
		* renewalMode - sets renewal mode:
			* null - auto, renew if it's time for it
			* 'skip' - do not renew
			* 'force' - renew
	* returns dict with:
		* type - provider type as initialized
		* identity - resolved identity
		* authResult - dict with lowlevel data:
			* authData - auth data extracted from req
			* tokenData - data extracted from token
			* renewalTokenInfo - token info used for renewal, structure is same as tokenInfo field returned by login()
			* renewal - renewal result ready to send to client, structure is same as result field returned by login()
	* can return AuthProblem object as an error, it's a [marked type](https://github.com/dimsmol/marked_types) and it's data field usually contains partially filled authResult structure of normal result, it's code field indicates type of problem:
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
* clearCookies(res) - clears auth cookies

Note, that req and res arguments accepted by any of AuthProvider's methods will be just passed to adapter and won't used by AuthProvider itself. So, you use non-standard req or res objects with your own adapter instead of HttpAdapter with no need to change anything in AuthProvider.

## Tokener

Creates and parses tokens. Too simple for most cases, but can be used as a base for your tokeners.

Token is a string guaranteed to contain only:

* base64 characters
* ':' character
* characters of key and algo used by signer and/or crypter
* your data characters (if not encrypted)

Note, that characters from your data may be left "as is", so you possibly will want to perform escaping or something.

Methods:

* setSigner(signer) - sets signer, usually Signer instance
* setCrypter(crypter) - sets crypter, usually Crypter instance
* setAlgoMaps(maps) - sets optional mapping for algorythm names substitution, allows to hide real argorythm names or substitute they with shorter codes within token
	* maps is a dict with two optional properties:
		* signer - map for signer algorythm names
		* crypter - map for crypter algorythm names
			* map is a dict where key is algorythm name as used by crypter or signer and value is a string to be used within created token instead of real algorythm name
			* Note, that if map is present, but no mapping is found for particular algorythm, exception will be thrown (you can change this by overriding getMissedAlgoMapping() method)
* createToken(data, opt_prefix) - creates token
	* expects data to be a string
	* token will be prepended with opt_prefix, that can be later obtained with Token.getPrefix()
* parseToken(token) - parses token
	* returns null if token cannot be parsed or signature is invalid
	* otherwise returns a dict:
		* data - token data as previously passed to createToken()
		* issued - when token was created, timestamp
* isValidIssued(issued, opt_allowedIssuedClockDeviation) - checks if issued is valid
	* is timestamp and is not too far in future (not further than on opt_allowedIssuedClockDeviation ms)
* isExpired(issued, maxAge) - checks if issued is expired
	* maxAge is in ms

Both createToken() and parseToken() will return null if token is not at least signed. It can happen, for example, if both signer and crypter are null. See also "Notes on Encryption" below.

Static methods:

* getPrefix(token, opt_separator) - extracts token prefix
	* opt_separator can be used for child classes overriding Tokener.prototype.separator

## AuthTokener

Creates and parses auth tokens. Is subclass of Tokener.

Number of Tokener methods made asynchronous to allow session-based token classes keeping the same interface.

Constructor:

* Tokener(opt_options)
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
* parseToken(token, additionalToken, cb) - extracts token data checking signature and handling additional token
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

## Notes on Encryption

### Signing

Encryption itself is not enough to protect your tokens. You must encrypt data then sign. Some encryption algorythms provide signing themselves, for all others you must use signing provided by authen.

Tokener ensures that data are at least signed (by Signer or by encryption algorythm). That's why you can get null from createToken() if signer is null even if crypter is not null.

Also, do not use the same secrets for encryption and for signing.

### Data Padding

Sometimes your data length can be guessed by token length. And then your data can be guessed by data length. It is especially true if your data are short, which is true for most tokens.

If, for example, your data length is 1 byte, there are only 256 varinants what they are.

Problem can still remain for relatively large data. For example, if data is stringifyed user id and you have 10005 users total, any data of size 5 indicates a user with id between 10000 and 10005 - only 6 possible variants.

Usually, encryption algorythm will extaned your data to the nearest block size and it will make guessing harder. But to be completely sure your data cannot by guessed by length, it's recommended to pad them to some certain length before encryption. You can do it overriding Tokener's packData() and unpackData() methods.

## License

MIT
