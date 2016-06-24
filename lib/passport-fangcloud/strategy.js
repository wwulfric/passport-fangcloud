/**
 * Module dependencies.
 */
var util = require('util')
, OAuth2Strategy = require('passport-oauth').OAuth2Strategy
, InternalOAuthError = require('passport-oauth').InternalOAuthError;

function Strategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL || 'https://oauth-server.fangcloud.net/oauth/authorize';
  options.tokenURL = options.tokenURL || 'https://oauth-server.fangcloud.net/oauth/token';
  options.scopeSeparator = options.scopeSeparator || ',';
  OAuth2Strategy.call(this, options, verify);
  this.name = 'fangcloud';

  this._oauth2.getOAuthAccessToken = function(code, params, callback) {
    var params = params || {};
    params['client_id'] = this._clientId;
    params['client_secret'] = this._clientSecret;
    var codeParam = (params.grant_type === 'refresh_token') ? 'refresh_token' : 'code';
    params[codeParam]= code;

    var post_data= querystring.stringify( params );
    var authorizationString = util.format('%s:%s', this._clientId, this._clientSecret);
    var buffer = new Buffer(authorizationString);
    var authorizationCode = buffer.toString('base64');
    var post_headers= {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': util.format('Basic %s', authorizationCode)
    };

    this._request("POST", this._getAccessTokenUrl(), post_headers, post_data, null, function(error, data, response) {
      if( error )  callback(error);
      else {
        var results;
        try {
          // As of http://tools.ietf.org/html/draft-ietf-oauth-v2-07
          // responses should be in JSON
          results= JSON.parse( data );
        }
        catch(e) {
          // .... However both Facebook + Github currently use rev05 of the spec
          // and neither seem to specify a content-type correctly in their response headers :(
          // clients of these services will suffer a *minor* performance cost of the exception
          // being thrown
          results= querystring.parse( data );
        }
        var access_token= results["access_token"];
        var refresh_token= results["refresh_token"];
        delete results["refresh_token"];
        callback(null, access_token, refresh_token, results); // callback results =-=
      }
    });
  };
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);
/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
