// Container readiness probe for the Lambda runtime emulator.
//
// It opens a TCP connection to the emulator's invoke port and closes it again.
// That is all it proves: the emulator is up and accepting connections.
//
// It must NEVER invoke the function, and that constraint is the whole reason
// the probe looks like this. The emulator serves one invocation at a time. A
// second invocation arriving while one is in flight makes it abort the
// in-flight request unanswered and exit its own process, which takes the
// container down with it. Docker runs this probe on its own schedule, every
// few seconds, for the container's whole life — so a probe that invokes lands
// on top of the harness's invocation sooner or later and kills the stack in
// the middle of a suite.
//
// What this probe no longer proves — that the built bundle actually answers —
// is proven twice elsewhere:
//
//   * the image build smoke-invokes every bundle it produces. The Dockerfile
//     beside this file runs src/edge/scripts/build-lambda-edge.mjs, which
//     imports the built handler, drives two routes through it, and deletes the
//     bundle on failure. A bundle that throws fails the build rather than the
//     first test.
//   * `wait_ready` in tests/e2e/harness/lambda_edge.py invokes /healthz once
//     per service before any test runs, from the single-threaded harness that
//     owns every other invocation.
//
// Moving the invocation out of here does leave one gap, and it is worth naming
// rather than implying full cover. The build-time smoke invoke runs under
// plain node, not under the emulator, and always loads index.mjs. A wrong
// `command:` on the no-wba service — which selects a different handler out of
// this same image — used to surface at stack-up as an unhealthy container. It
// now surfaces about ninety seconds later out of `wait_ready`, carrying the
// function's own error text. Later and from somewhere else, not lost.
//
// The image ships node but no curl, so the probe is a node script.

import { Socket } from 'node:net';

// The emulator's invoke port inside the container, fixed by the runtime image.
const PORT = 8080;

// Deliberately shorter than the compose healthcheck `timeout`, so a stuck
// connect exits with a status this script chose rather than being killed.
const DEADLINE_MS = 2000;

const socket = new Socket();

// A plain timer rather than socket.setTimeout: that one is an idle timer whose
// behaviour during the connect phase varies by node version. Both exit paths
// clear it, because a pending timer keeps the event loop alive and would make
// every probe linger for the full deadline.
const timer = setTimeout(() => {
  socket.destroy();
  process.exit(1);
}, DEADLINE_MS);

// Registered before connect() so there is no window in which an `error` event
// has no listener — an unhandled socket error throws.
socket.on('error', () => {
  clearTimeout(timer);
  process.exit(1);
});

socket.on('connect', () => {
  clearTimeout(timer);
  socket.destroy();
  process.exit(0);
});

socket.connect(PORT, '127.0.0.1');
