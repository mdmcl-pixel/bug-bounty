import assert from "node:assert/strict";
import test from "node:test";

import { errorHandler } from "../middleware/errorHandler.js";

function createResponse() {
  return {
    headersSent: false,
    statusCode: null,
    body: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(body) {
      this.body = body;
      return this;
    },
  };
}

test("errorHandler maps malformed JSON parse failures to a safe HTTP 400 response", () => {
  const res = createResponse();
  const err = {
    type: "entity.parse.failed",
    status: 400,
    body: "{secret malformed input",
  };

  errorHandler(err, {}, res, () => {
    assert.fail("next should not be called");
  });

  assert.equal(res.statusCode, 400);
  assert.deepEqual(res.body, {
    success: false,
    message: "Malformed JSON request body",
  });
  assert.equal(JSON.stringify(res.body).includes(err.body), false);
});

test("errorHandler preserves HTTP 500 for unrelated unexpected errors", () => {
  const res = createResponse();

  errorHandler(new Error("database exploded"), {}, res, () => {
    assert.fail("next should not be called");
  });

  assert.equal(res.statusCode, 500);
  assert.deepEqual(res.body, {
    success: false,
    message: "Unexpected server error",
  });
});
