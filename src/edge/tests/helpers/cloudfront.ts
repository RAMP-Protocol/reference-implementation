import type { CloudFrontEdgeEvent, CloudFrontRequest } from 'hono/lambda-edge';

// makeViewerRequestEvent builds the CloudFront viewer-request event shape the
// Lambda@Edge suites drive the handler with: GET for the given URL, the Host
// header CloudFront always forwards, plus any extra headers a case needs.
// Shared here so the event shape cannot drift between the proxy-mode suite
// (aws-handler) and the pass-through suite (aws-pass-through).
export function makeViewerRequestEvent(
  urlStr: string,
  headers: Record<string, string> = {},
): CloudFrontEdgeEvent {
  const url = new URL(urlStr);
  const cfHeaders: CloudFrontRequest['headers'] = {};
  cfHeaders.host = [{ key: 'Host', value: url.host }];
  for (const [k, v] of Object.entries(headers)) {
    cfHeaders[k.toLowerCase()] = [{ key: k, value: v }];
  }
  return {
    Records: [
      {
        cf: {
          config: {
            distributionDomainName: 'test.cloudfront.net',
            distributionId: 'EXAMPLE',
            eventType: 'viewer-request',
            requestId: 'req-1',
          },
          request: {
            clientIp: '127.0.0.1',
            method: 'GET',
            uri: url.pathname,
            querystring: url.search.slice(1),
            headers: cfHeaders,
          },
        },
      },
    ],
  };
}
