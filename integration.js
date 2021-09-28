'use strict';
const request = require('request');
const Bottleneck = require('bottleneck/es5');
const _ = require('lodash');
const config = require('./config/config');
const fs = require('fs');
let Logger;
let requestWithDefaults;
let limiter = null;

function startup(logger) {
  let defaults = {};
  Logger = logger;
  const { cert, key, passphrase, ca, proxy, rejectUnauthorized } = config.request;
  if (typeof cert === 'string' && cert.length > 0) {
    defaults.cert = fs.readFileSync(cert);
  }
  if (typeof key === 'string' && key.length > 0) {
    defaults.key = fs.readFileSync(key);
  }
  if (typeof passphrase === 'string' && passphrase.length > 0) {
    defaults.passphrase = passphrase;
  }
  if (typeof ca === 'string' && ca.length > 0) {
    defaults.ca = fs.readFileSync(ca);
  }
  if (typeof proxy === 'string' && proxy.length > 0) {
    defaults.proxy = proxy;
  }
  if (typeof rejectUnauthorized === 'boolean') {
    defaults.rejectUnauthorized = rejectUnauthorized;
  }
  requestWithDefaults = request.defaults(defaults);
}

function _setupLimiter(options) {
  limiter = new Bottleneck({
    maxConcurrent: Number.parseInt(options.maxConcurrent, 10), // no more than 5 lookups can be running at single time
    highWater: 100, // no more than 100 lookups can be queued up
    strategy: Bottleneck.strategy.OVERFLOW,
    minTime: Number.parseInt(options.minTime, 10) // don't run lookups faster than 1 every 200 ms
  });
}

function _lookupEntity(entity, options, cb) {
  let requestOptions = {
    method: 'GET',
    uri: `https://api.attackerkb.com/v1/topics`,
    headers: {
      Authorization: 'basic ' + options.apiKey
    },
    json: true
  };
  if (options.publicOnly === true) {
    requestOptions.qs = {
      name: entity.value,
      size: options.resultCount,
      sort: 'revisionDate:desc',
      metadata: 'PUBLIC'
    };
  } else if (options.publicOnly === false) {
    requestOptions.qs = {
      name: entity.value,
      size: options.resultCount,
      sort: 'revisionDate:desc'
    };
  } else {
    return;
  }

  Logger.trace({ requestOptions }, 'Request Options');

  requestWithDefaults(requestOptions, function (err, res, body) {
    if (err) {
      Logger.error(err, 'Request Error');
      return cb({
        detail: 'Unexpected HTTP error',
        error: err
      });
    }

    if (res && res.statusCode === 200) {
      if (Array.isArray(res.body.data) && res.body.data.length > 0) {
        return cb(null, {
          entity,
          data: {
            summary: getSummary(res),
            details: res.body.data
          }
        });
      } else {
        return cb(null, {
          entity,
          data: null
        });
      }
    }

    if (res && res.statusCode && res.statusCode === 404) {
      return cb(null, { entity, data: null });
    }

    const errorMsg = res && res.body && res.body.message;

    if ((res && res.statusCode === 401) || (res && res.statusCode === 403)) {
      return cb(null, {
        entity,
        isVolatile: true,
        data: {
          summary: [' ! Invalid API Key'],
          details: {
            errorMessage: `${errorMsg} Ensure you are using a valid API key.`,
            summaryTag: 'Invalid API Key',
            allowRetry: false
          }
        }
      });
    }

    cb({
      statusCode: res.statusCode,
      detail: errorMsg ? errorMsg : `Unexpected ${res.statusCode} status code received`
    });
  });
}

function getSummary(res) {
  let tags = [];
  if (res && res.body) {
    const { data } = res.body;
    // ask about this in review, summary not rendering in overlay
    for (const block of data) {
      tags.push(`Attacker Value Score: ${block.score.attackerValue}`);
      tags.push(`Exploitability Score: ${block.score.exploitability}`);
      tags.push(`Name: ${block.name}`);
    }
  }
  Logger.trace({ TAGS: tags });
  return tags;
}

function doLookup(entities, options, cb) {
  const lookupResults = [];
  const errors = [];
  let numConnectionResets = 0;
  let numThrottled = 0;
  let numGatewayTimeouts = 0;
  let hasValidIndicator = false;
  Logger.trace({ entities }, 'doLookup');

  if (!limiter) _setupLimiter(options);

  entities.forEach((entity) => {
    hasValidIndicator = true;
    limiter.submit(_lookupEntity, entity, options, (err, result) => {
      const maxRequestQueueLimitHit =
        (result && result.message) || (_.isEmpty(err) && _.isEmpty(result))
          ? true
          : false;

      const statusCode = _.get(err, 'statusCode', '');
      const isGatewayTimeout =
        statusCode === 502 || statusCode === 504 || statusCode === 500;
      const isConnectionReset = _.get(err, 'error.code', '') === 'ECONNRESET';

      if (maxRequestQueueLimitHit || isConnectionReset || isGatewayTimeout) {
        // Tracking for logging purposes
        if (isConnectionReset) numConnectionResets++;
        if (maxRequestQueueLimitHit) numThrottled++;
        if (isGatewayTimeout) numGatewayTimeouts++;

        lookupResults.push({
          entity,
          isVolatile: true,
          data: {
            summary: ['! Search limit reached'],
            details: {
              maxRequestQueueLimitHit,
              isConnectionReset,
              isGatewayTimeout,
              errorMessage:
                'A temporary AttackerKB search limit was reached. You can retry your search by pressing the "Retry Search" button.'
            }
          }
        });
      } else if (err) {
        errors.push(err);
      } else {
        lookupResults.push(result);
      }

      if (lookupResults.length + errors.length === entities.length) {
        if (numConnectionResets > 0 || numThrottled > 0) {
          Logger.warn(
            {
              numEntitiesLookedUp: entities.length,
              numConnectionResets: numConnectionResets,
              numGatewayTimeouts: numGatewayTimeouts,
              numLookupsThrottled: numThrottled
            },
            'Lookup Limit Error'
          );
        }
        // we got all our results
        if (errors.length > 0) {
          cb(errors);
        } else {
          Logger.trace({ lookupResults }, 'lookup Results');
          cb(null, lookupResults);
        }
      }
    });
  });

  if (!hasValidIndicator) {
    cb(null, []);
  }
}

function onMessage(payload, options, callback) {
  switch (payload.action) {
    case 'RETRY_LOOKUP':
      doLookup([payload.entity], options, (err, lookupResults) => {
        if (err) {
          Logger.error({ err }, 'Error retrying lookup');
          callback(err);
        } else {
          callback(
            null,
            lookupResults && lookupResults[0] && lookupResults[0].data === null
              ? { data: { summary: ['No Results Found on Retry'] } }
              : lookupResults[0]
          );
        }
      });
      break;
  }
}

function validateOption(errors, options, optionName, errMessage) {
  if (
    typeof options[optionName].value !== 'string' ||
    (typeof options[optionName].value === 'string' &&
      options[optionName].value.length === 0)
  ) {
    errors.push({
      key: optionName,
      message: errMessage
    });
  }
}

function validateOptions(options, callback) {
  let errors = [];
  validateOption(errors, options, 'apiKey', 'You must provide a valid API Key.');
  callback(null, errors);
}

module.exports = {
  doLookup: doLookup,
  onMessage: onMessage,
  validateOptions: validateOptions,
  startup: startup
};
