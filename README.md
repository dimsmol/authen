# authen

Solves following problems:

* Passwords hashing for storing them on server-side and validation against the hashes
* Signing data (any buffer) with secret
* Creation of auth tokens, validating them, carrying renewal, expiration and revocation

Additional tools:

* Constant time equals for timing attacks prevention (tools/crypto)
* Url-safe base64 encoder/decoder (tools/url_safe_base64)

## Pwd

Password hashing tool.

* hash(pwd, cb)
* verify(pwd, hash, cb)

## Signer

Data signer producing "tokens" containing:

* data itself (url-safe base64 encoded)
* name of algorythm used for signing
* key used to choose secret for singing

All the parts are separated by ':', token itself is pretty much url safe.

* new Signer(options), where options are:
	* secrets - list of secrets available for signing and unsigning
	* currentKey - key to choose secret for signing (alphanumeric chars, underscores and '-' are allowed)
		* key to choose secret for unsigning is a part of token

* sign(buffer) -> token
* unsign(token) -> buffer

## Tokener

Tokener is designed to be protocol-independent, but has number of utility methods that can be helpful if you're using http and are willing to send and recieve your tokens using cookies and http headers.

* new Tokener(signer, opt_options, opt_identityEqualsFunc, opt_getLastRevocationTimeFunc)
	* signer is a Signer or Signer-like object
	* options are complex enough, some aspects are described below, see sources for full reference and defaults
	* identityEqualsFunc(identityA, identityB) can be used for identities that are coplex structures instead of simple types such as integer or string ids. If not set, '===' operator will be used to check equality.
	* getLastRevocationTimeFunc(token) is required (and highly recommended) to use ability to revoke previously issued tokens. Must return point in time when revocation was performed last time for identity represented by the token or null if no revocations were performed. If not set, no revocation checks will be performed.

* login(identity) -> tokenResult - creates token for given identity and returns information about it along with itself
	* tokenResult is `{ identity: loggedInIdentity, token: token, issued: issuedDate, maxAge: maxAgeMilliseconds }`
	* login() expects you are managing token (storing, deleting on logout) yourself
	* token then must be provided within options.headers.name request header for every request
* loginWithCookies(res, identity, isSessionLifetime) -> tokenResult - the same as login(), but tokenResult will not contain token itself, instead it will be placed to cookies. isSessionLifetime when true indicates that cookies must have browser's session lifetime
	* by default pair of cookies is issued and it's expected that you copy value of one of them named options.cookies.nameLimited to options.headers.name request header for every request
		* this is needed for CSRF protection, see below for details and other options available
* logoutWithCookies(res) - removes cookies set by loginWithCookies()
	* you don't need to call it if you used login() instead of loginWithCookies()
* auth(token, opt_additionalToken, opt_expectedIdentity, opt_noCookiesMode) -> tokenData - checks auth token and provides it's data if it is valid one and renewal info if needed, null returned if token is not valid by any reason. auth() can also return `{ unexpectedIdentity: true }` if got unexpected identity (see below).
	* additionalToken can be used to provide additional token if there is a chance that 'token' is lmited one (related to CSRF protection, see below)
	* expectedIdentity can be used to get sure token describes identity we expect (see "Unexpected identity protection" below)
	* noCookesMode, when true, indicates that we have no access to cookies or don't want to use them. This will omit renewal generation for cookie-tokens, because we will unable to use such a renewal. This argument is useful only if you're using cookie-stored tokens in general, but sometimes are unable or not willing to set cookies for renewal.
	* tokenData is `{ auth: { identity: identity, ..other token data.. }, renewal: renewalData }`
	* auth() checks:
		* token is properly signed according to signer
		* token is not expired accoring to options.maxAge
		* if token is limited:
			* additionalToken is provided and it is correct
			* additionalToken matches token
		* token is not revoked
			* token is not issued as a renewal too close to last revocation (see "Token revocation" below)
		* identity matches expectedIdentity (if provided)
	* if renewal is needed, auth() also provides renewal data
* applyRenewal(res, renewal) - applies renewal data provided by previously called auth()
* getAuthData(req) -> authData - harvests auth data from http headers and cookies
	* authData are `{ token: token, additionalToken: optionalAdditionalToken, expectedIdentity: optionalExpectedIdentity }`
		* expected identity assumed to be JSON-encoded when placed to http header, will be skipped if cannot be parsed

### identity

Identity is used to identificate authentication target - user, service or whatever entity participating in authentication process. Usually it is just a user id, represented by integer or string value. But it is allowed to be any JSON-encodable structure.

Of course, to check complex identities equality we need something more sophisticated than basic equality operator provided by JS. For that purpose identityEqualsFunc(identityA, identityB) is used.

### Unexpected identity protection

If auth token is stored in cookies or other storage shared between browser tabs, user can login on one tab as user A and then relogin on other tab as user B. First tab will then use new tokens (because it gets them from storage shared between tabs).

But application instance running on first tab doesn't know (unless some kind of inter-tab notification is involved) that user is changed. So it will continue to show data rendered for user A, but all subsequent requests will be performed as if they done by user B (with user B token).

Such a mix can be highly undesirable. To avoid this situation, application can tell what user is expected to be represented by token sending to server. You can set options.headers.nameExpected http header on client side to JSON-serialized identity, then use this value on server - extract it with getAuthData() and provide as an argument to auth(). auth() then will check that identity represented by token matches expected one. If not, you can respond some error to client, to notify it that there possibly was a relogin it missed.

### Built-in CSRF protection

If client provides authentication cookie, it doesn't make us sure that request is intentionally performed by the entity owning such a cookie. That's because browser sends cookies along with request to domain cookies are belong to, no matter what code or page did the request.

So, to prove that request is performed by the code that itself has access to authentication cookies, the code should copy some token from cookies to request header. You could use authetication token itself for such a purpose - copy auth token from cookie to header to ensure server you have access to it. But if you use http-only cookie for auth token, then you cannot do it from JS.

By default Tokener sets two auth cookies. One is for regular http-only auth token and second one is "limited" and not-http-only (so, it's available to JS). Tokener expects limited cookie to be copied to request header. If header contains limited cookie, Tokener will also check first, http-only cookie and ensure that limited token matches regular one, then authentication will be succesful.

Altrenatives available:

* If you're using your own CSRF protection mechanism, just set options.cookies.useLimited to false. Then Tokener will look at cookies even if no auth token (limited or not) is provided within headers.
* If by any reason you want your auth cookie to be non-http-only, then along with setting set options.cookies.useLimited to false, set options.cookies.forceNonHttp to true. Then tokener will set main auth cookie without http-only flag and you can copy it to header without the need of second limited cookie.
* If you don't want server to rely on cookies at all, prefer use login() method instead of loginWithCookies(), store auth token where you want and provide it within every request header.

### Token expiration

Token treated as expired if more than options.maxAge amount of time passed since it was issued.

### Token renewal

If auth() got valid token and more than options.renewal.interval amount of time passed since it was issued, then it returns renewal data for such a token. Renewal data then can be applied using applyRenewal().

Renewed token will mimic all properties of original one, including whether it is cookie token or not and if it is cookie token, should it have browser session lifetime or not. The only difference is that unlike renewed tokens, tokens obtained by providing password are marked as "strong" and are tolerant to revocation trust delay described below.

### Token revocation

getLastRevocationTimeFunc(token) must return last revocation time. All tokens issued before that time will be treated as invalid (revoked), as well as tokens that were renewed (see renewal) within options.postRevocationTrustDelay interval after that time.

Revocation trust delay is needed to disallow keeping compromised token alive by continuous renewal. Renewals close to revocation moment will be discarded to insure we're using only renewed tokens obtained after all servers informed about revocation.
