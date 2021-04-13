/**
 * Module dependencies.
 */
var util = require('util')
  , OAuth2Strategy = require('passport-oauth2')
  , InternalOAuthError = require('passport-oauth2').InternalOAuthError;


/**
 * `Strategy` constructor.
 *
 * The Fitbit authentication strategy authenticates requests by delegating to
 * Fitbit using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your Fitbit application's client id
 *   - `clientSecret`  your Fitbit application's client secret
 *   - `callbackURL`   URL to which Fitbit will redirect the user after granting authorization
 *
 * Examples:
 *
 *     passport.use(new FitbitStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/fitbit/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL || 'https://www.fitbit.com/oauth2/authorize';
  options.tokenURL = options.tokenURL || 'https://api.fitbit.com/oauth2/token';
  options.scopeSeparator = options.scopeSeparator || ' ';
  options.customHeaders = {
    Authorization:  'Basic '+ new Buffer(options.clientID + ':' + options.clientSecret).toString('base64')
  };

  OAuth2Strategy.call(this, options, verify);
  this.name = 'fitbit';
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);

Strategy.prototype.authenticate = function(req, options) {
  options || (options = {});

  OAuth2Strategy.prototype.authenticate.call(this, req, options);
};

/**
 * Return extra parameters to be included in the request token
 * request.
 *
 * @param {Object} options
 * @return {Object}
 * @api protected
 */
Strategy.prototype.authorizationParams = function(options) {
  var params = options || {};

  var scope = options.scope;
  if (scope) {
    params['scope'] = Array.isArray(scope) ? scope.join(' ') : scope;
  }
  return params;
}

/**
 * Expose `Strategy` directly from package.
 */
exports = module.exports = Strategy;

/**
 * Export constructors.
 */
exports.Strategy = Strategy;
