/* eslint-env node */
/* eslint no-use-before-define: [0, "nofunc"] */
'use strict';

// sources of inspiration:
// https://web-identity-federation-playground.s3.amazonaws.com/js/sigv4.js
// http://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
var crypto = require('crypto');
var querystring = require('querystring');

exports.createCanonicalRequest = function(method, pathname, query, headers, payload) {
  return [
    method.toUpperCase(),
    pathname,
    exports.createCanonicalQueryString(query),
    exports.createCanonicalHeaders(headers),
    exports.createSignedHeaders(headers),
    payload
  ].join('\n');
};

exports.createCanonicalQueryString = function(params) {
  return Object.keys(params).sort().map(function(key) {
    return encodeURIComponent(key) + '=' + encodeURIComponent(params[key]);
  }).join('&');
};

exports.createCanonicalHeaders = function(headers) {
  return Object.keys(headers).sort().map(function(name) {
    return name.toLowerCase().trim() + ':' + headers[name].toString().trim() + '\n';
  }).join('');
};

exports.createSignedHeaders = function(headers) {
  return Object.keys(headers).sort().map(function(name) {
    return name.toLowerCase().trim();
  }).join(';');
};

exports.createCredentialScope = function(time, region, service) {
  return [toDate(time), region, service, 'aws4_request'].join('/');
};

exports.createStringToSign = function(time, region, service, request) {
  return [
    'AWS4-HMAC-SHA256',
    toTime(time),
    exports.createCredentialScope(time, region, service),
    hash(request, 'hex')
  ].join('\n');
};

exports.createSignature = function(secret, time, region, service, stringToSign) {
  var h1 = hmac('AWS4' + secret, toDate(time)); // date-key
  var h2 = hmac(h1, region); // region-key
  var h3 = hmac(h2, service); // service-key
  var h4 = hmac(h3, 'aws4_request'); // signing-key
  return hmac(h4, stringToSign, 'hex');
};

exports.createPresignedS3URL = function(name, options) {
  options = options || {};
  options.method = options.method || 'GET';
  options.bucket = options.bucket || process.env.AWS_S3_BUCKET;
  return exports.createPresignedURL(
    options.method,
    options.bucket + '.s3.amazonaws.com',
    '/' + name,
    's3',
    'UNSIGNED-PAYLOAD',
    options
  );
};

exports.createPresignedURL = function(method, host, path, service, payload, options) {
  options = options || {};
  options.key = options.key || process.env.AWS_ACCESS_KEY_ID;
  options.secret = options.secret || process.env.AWS_SECRET_ACCESS_KEY;
  options.protocol = options.protocol || 'https';
  options.headers = options.headers || {};
  options.timestamp = options.timestamp || Date.now();
  options.region = options.region || process.env.AWS_REGION || 'us-east-1';
  options.expires = options.expires || 86400; // 24 hours
  options.headers = options.headers || {};

  // host is required
  options.headers.Host = host;

  var query = options.query ? querystring.parse(options.query) : {};
  query['X-Amz-Algorithm'] = 'AWS4-HMAC-SHA256';
  query['X-Amz-Credential'] = options.key + '/' + exports.createCredentialScope(options.timestamp, options.region, service);
  query['X-Amz-Date'] = toTime(options.timestamp);
  query['X-Amz-Expires'] = options.expires;
  query['X-Amz-SignedHeaders'] = exports.createSignedHeaders(options.headers);

  var canonicalRequest = exports.createCanonicalRequest(method, path, query, options.headers, payload);
  var stringToSign = exports.createStringToSign(options.timestamp, options.region, service, canonicalRequest);
  var signature = exports.createSignature(options.secret, options.timestamp, options.region, service, stringToSign);
  query['X-Amz-Signature'] = signature;
  return options.protocol + '://' + host + path + '?' + querystring.stringify(query);
};

exports.generatePolicy = function(expiry, bucket, acl, redirect, uuid, key, date, region, service, conditions) {
  return {
    expiration: expiry.toISOString(),
    conditions: [
      { bucket : bucket },
      { acl : acl },
      { success_action_redirect : redirect },
      {"x-amz-meta-uuid": uuid },
      {"x-amz-server-side-encryption": "AES256"},
      {"x-amz-credential": key+'/'+toDate(date)+'/'+region+'/'+service+'/aws4_request'},
      {"x-amz-algorithm": "AWS4-HMAC-SHA256"},
      {"x-amz-date": toTime(date) }
    ].concat(conditions||[])
  };
}

exports.createS3FormFields = function(options) {
  var expiry = new Date(),
  date = options.date || new Date(),
  acl = options.acl || 'public-read',
  uuid = options.uuid || Math.random().toString(10).substring(2),
  region = options.region || 'us-east-1',
  service = 's3';
  expiry.setSeconds(expiry.getSeconds()+(options.expiry || 86400));
  var policy = exports.generatePolicy(expiry,
    options.bucket,
    acl,
    options.redirect,
    uuid,
    options.key,
    date,
    region,
    service,
    options.conditions),
  base64Policy = new Buffer(JSON.stringify(policy)).toString('base64'),
  signature = exports.createSignature(options.secret,date,region,service,base64Policy),
  formFields = {
    acl : acl,
    success_action_redirect : options.redirect,
    'x-amz-meta-uuid' : uuid,
    'x-amz-server-side-encryption' : 'AES256',
    'X-Amz-Credential' : options.key+'/'+toDate(date)+'/'+region+'/'+service+'/aws4_request',
    'X-Amz-Algorithm' : 'AWS4-HMAC-SHA256',
    'X-Amz-Date' : toTime(date),
    'Policy' : base64Policy,
    'X-Amz-Signature' : signature
  };
  if (options.objectKey) {
    formFields['key'] = options.objectKey;
  }
  if (options.contentType) {
    formFields['Content-Type'] = options.contentType;
  }
  if (options.metaTag) {
    formFields['x-amz-meta-tag'] = options.metaTag;
  }
  return formFields;
}

function toTime(time) {
  return new Date(time).toISOString().replace(/[:\-]|\.\d{3}/g, '');
}

function toDate(time) {
  return toTime(time).substring(0, 8);
}

function hmac(key, string, encoding) {
  return crypto.createHmac('sha256', key)
    .update(string, 'utf8')
    .digest(encoding);
}

function hash(string, encoding) {
  return crypto.createHash('sha256')
    .update(string, 'utf8')
    .digest(encoding);
}
