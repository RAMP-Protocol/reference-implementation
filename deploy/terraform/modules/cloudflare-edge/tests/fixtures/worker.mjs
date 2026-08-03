// Test fixture standing in for the built worker bundle (src/edge/dist/worker.mjs).
// The tests only check that the module uploads file content verbatim.
export default { fetch: () => new Response("test-fixture") };
