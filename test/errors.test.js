const nock = require('nock');
const { doLookup, startup } = require('../integration');
jest.setTimeout(10000);

const options = {
  apiKey: '12345',
  resultCount: 5,
  publicOnly: true,
  maxConcurrent: 10,
  minTime: 1
};

const cve = {
  type: 'cve',
  value: 'CVE-2008-5161'
};

const Logger = {
  trace: (args, msg) => {
    console.info(msg, args);
  },
  info: (args, msg) => {
    console.info(msg, args);
  },
  error: (args, msg) => {
    console.error(msg, args);
  },
  debug: (args, msg) => {
    console.info(msg, args);
  },
  warn: (args, msg) => {
    console.info(msg, args);
  }
};

beforeAll(() => {
  startup(Logger);
});

test('502 response should result in `isGatewayTimeout`', (done) => {
  const scope = nock(`https://api.attackerkb.com/v1/topics`).get(/.*/).reply(502);
  doLookup([cve], options, (err, lookupResults) => {
    //console.info(JSON.stringify(lookupResults, null, 4));
    expect(lookupResults.length).toBe(1);
    const details = lookupResults[0].data.details;
    expect(details.maxRequestQueueLimitHit).toBe(false);
    expect(details.isConnectionReset).toBe(false);
    expect(details.isGatewayTimeout).toBe(true);
    done();
  });
});

test('504 response should result in `isGatewayTimeout`', (done) => {
  const scope = nock(`https://api.attackerkb.com/v1/topics`).get(/.*/).reply(504);
  doLookup([cve], options, (err, lookupResults) => {
    //console.info(JSON.stringify(lookupResults, null, 4));
    expect(lookupResults.length).toBe(1);
    const details = lookupResults[0].data.details;
    expect(details.maxRequestQueueLimitHit).toBe(false);
    expect(details.isConnectionReset).toBe(false);
    expect(details.isGatewayTimeout).toBe(true);
    done();
  });
});

test('ECONNRESET response should result in `isConnectionReset`', (done) => {
  const scope = nock(`https://api.attackerkb.com/v1/topics`)
    .get(/.*/)
    .replyWithError({ code: 'ECONNRESET' });
  doLookup([cve], options, (err, lookupResults) => {
    // console.info(JSON.stringify(lookupResults, null, 4));
    expect(lookupResults.length).toBe(1);
    const details = lookupResults[0].data.details;
    expect(details.maxRequestQueueLimitHit).toBe(false);
    expect(details.isConnectionReset).toBe(true);
    expect(details.isGatewayTimeout).toBe(false);
    done();
  });
});

test('500 response should return a normal integration error', (done) => {
  const scope = nock(`https://api.attackerkb.com/v1/topics`).get(/.*/).reply(500);
  doLookup([cve], options, (err, lookupResults) => {
    // console.info(JSON.stringify(err, null, 4));
    expect(err.length).toBe(1);
    expect(err[0].statusCode).toBe(500);
    done();
  });
});
