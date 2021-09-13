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
    highWater: 50, // no more than 50 lookups can be queued up
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

  requestWithDefaults(requestOptions, function (error, res, body) {
    let processedResult = handleRestError(error, entity, res, body);

    if (processedResult.error) {
      cb(processedResult);
      return;
    }

    cb(null, processedResult);
    return;
  });
}

function doLookup(entities, options, cb) {
  const lookupResults = [];
  const errors = [];
  let numConnectionResets = 0;
  let numThrottled = 0;
  let hasValidIndicator = false;
  Logger.debug(entities);

  if (!limiter) _setupLimiter(options);

  _setupLimiter(options);

  entities.forEach((entity) => {
    hasValidIndicator = true;
    limiter.submit(_lookupEntity, entity, options, (err, result) => {
      const maxRequestQueueLimitHit =
        (_.isEmpty(err) && _.isEmpty(result)) ||
        (err && err.message === 'This job has been dropped by Bottleneck');

      const isConnectionReset =
        _.get(err, 'errors[0].meta.err.code', '') === 'ECONNRESET';

      if (maxRequestQueueLimitHit || isConnectionReset) {
        // Tracking for logging purposes
        if (isConnectionReset) numConnectionResets++;
        if (maxRequestQueueLimitHit) numThrottled++;

        lookupResults.push({
          entity,
          isVolatile: true, // prevent limit reached results from being cached
          data: {
            summary: ['Lookup limit reached'],
            details: {
              maxRequestQueueLimitHit,
              isConnectionReset
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
          log.warn(
            {
              numEntitiesLookedUp: entities.length,
              numConnectionResets: numConnectionResets,
              numLookupsThrottled: numThrottled
            },
            'Lookup Limit Error'
          );
        }
        // we got all our results
        if (errors.length > 0) {
          cb(errors);
        } else {
          // I can log the results before the callback is called.
          cb(null, lookupResults);
        }
      }
    });
  });

  if (!hasValidIndicator) {
    cb(null, []);
  }
}

function handleRestError(error, entity, res, body) {
  let result;

  if (error) {
    return {
      error: error,
      detail: 'HTTP Request Error'
    };
  }

  if (res.statusCode === 200) {
    // we got data!
    result = {
      entity: entity,
      body: body
    };
  } else if (res.statusCode === 400) {
    result = {
      error: 'Bad Request',
      detail: body.query_status
    };
  } else if (res.statusCode === 401) {
    result = {
      error: 'Unauthorized',
      detail: body.query_status
    };
  } else if (res.statusCode === 404) {
    result = {
      error: 'Not Found',
      detail: body.query_status
    };
  } else if (res.statusCode === 429) {
    result = {
      error: 'Rate Limit Exceeded',
      detail: body.query_status
    };
  } else if (res.statusCode === 500) {
    result = {
      error: 'Failed to retrieve topics',
      detail: body.query_status
    };
  } else {
    result = {
      error: 'Unexpected Error',
      statusCode: res ? res.statusCode : 'Unknown',
      detail: 'An unexpected error occurred'
    };
  }

  return result;
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
  validateOptions: validateOptions,
  startup: startup
};
