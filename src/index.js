'use strict';

var awsSignature = require('aws-signature-v4');

var crypto = require('crypto');

module.exports.getUtil = function(region, endpoint, credentials) {

  var sign = function sign(credentials, expiration) {
    var url = awsSignature.createPresignedURL('GET', endpoint, '/mqtt', 'iotdevicegateway', crypto.createHash('sha256').update('', 'utf8').digest('hex'), {
      key: credentials.accessKeyId,
      secret: credentials.secretAccessKey,
      region: region,
      expires: expiration,
      protocol: 'wss'
    });
    if (credentials.sessionToken) {
      url += '&X-Amz-Security-Token=' + encodeURIComponent(credentials.sessionToken);
    }
    return url;
  };

  return {
    getSignedUrl: function(expiration, callback) {
      credentials.get(function (err) {
        if (err) return callback(err);
        var url = sign(credentials, expiration);
        callback(null, url);
      });
    }
  };
};

/*
var AWS = require('aws-sdk');

module.exports.getUtil2 = function(region, endpoint, credentials) {
  return {
    getAndSign: function getAndSign(expiration, callback) {
        var url = getSignedUrl(endpoint, region, credentials, expiration);
        callback(null, url);
    }
  };
};

function getSignatureKey(key, date, region, service) {

    var kDate = AWS.util.crypto.hmac('AWS4' + key, date, 'buffer');
    var kRegion = AWS.util.crypto.hmac(kDate, region, 'buffer');
    var kService = AWS.util.crypto.hmac(kRegion, service, 'buffer');
    var kCredentials = AWS.util.crypto.hmac(kService, 'aws4_request', 'buffer');    
    return kCredentials;
};

function getSignedUrl(host, region, credentials, expiration) {
    var datetime = AWS.util.date.iso8601(new Date()).replace(/[:\-]|\.\d{3}/g, '');
    var date = datetime.substr(0, 8);

    var method = 'GET';
    var protocol = 'wss';
    var uri = '/mqtt';
    var service = 'iotdevicegateway';
    var algorithm = 'AWS4-HMAC-SHA256';

    var credentialScope = date + '/' + region + '/' + service + '/' + 'aws4_request';
    var canonicalQuerystring = 'X-Amz-Algorithm=' + algorithm;
    canonicalQuerystring += '&X-Amz-Credential=' + encodeURIComponent(credentials.accessKeyId + '/' + credentialScope);
    canonicalQuerystring += '&X-Amz-Date=' + datetime;
    canonicalQuerystring += '&X-Amz-Expires=' + expiration || 86400;
    canonicalQuerystring += '&X-Amz-SignedHeaders=host';

    var canonicalHeaders = 'host:' + host + '\n';
    var payloadHash = AWS.util.crypto.sha256('', 'hex')
    var canonicalRequest = method + '\n' + uri + '\n' + canonicalQuerystring + '\n' + canonicalHeaders + '\nhost\n' + payloadHash;

    var stringToSign = algorithm + '\n' + datetime + '\n' + credentialScope + '\n' + AWS.util.crypto.sha256(canonicalRequest, 'hex');
    var signingKey = getSignatureKey(credentials.secretAccessKey, date, region, service);
    var signature = AWS.util.crypto.hmac(signingKey, stringToSign, 'hex');

    canonicalQuerystring += '&X-Amz-Signature=' + signature;
    if (credentials.sessionToken) {
        canonicalQuerystring += '&X-Amz-Security-Token=' + encodeURIComponent(credentials.sessionToken);
    }

    var requestUrl = protocol + '://' + host + uri + '?' + canonicalQuerystring;
    return requestUrl;
};
*/