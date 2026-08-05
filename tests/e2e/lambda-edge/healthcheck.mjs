// Container healthcheck for the Lambda runtime emulator.
//
// The emulator exposes ONE route — the invoke endpoint — so readiness cannot be
// probed with a plain GET the way the other edges are. This invokes the
// function the way the tests do: a CloudFront viewer-request event for the
// worker's /healthz route, which answers a generated 200. Exit 0 only when that
// exact answer comes back, so a container whose bundle throws on its first
// invocation is reported unhealthy rather than started.

import { request } from 'node:http';

const event = {
  Records: [
    {
      cf: {
        config: {
          distributionDomainName: 'healthcheck.cloudfront.example',
          distributionId: 'HEALTHCHECK',
          eventType: 'viewer-request',
          requestId: 'healthcheck',
        },
        request: {
          clientIp: '127.0.0.1',
          method: 'GET',
          uri: '/healthz',
          querystring: '',
          headers: { host: [{ key: 'Host', value: 'healthcheck.invalid' }] },
        },
      },
    },
  ],
};

const body = JSON.stringify(event);
const req = request(
  {
    host: '127.0.0.1',
    port: 8080,
    path: '/2015-03-31/functions/function/invocations',
    method: 'POST',
    headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) },
  },
  (res) => {
    let text = '';
    res.on('data', (chunk) => {
      text += chunk;
    });
    res.on('end', () => {
      try {
        process.exit(JSON.parse(text).status === '200' ? 0 : 1);
      } catch {
        process.exit(1);
      }
    });
  },
);
req.on('error', () => process.exit(1));
req.end(body);
