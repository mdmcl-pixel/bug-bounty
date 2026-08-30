import assert from "node:assert/strict";
import test from "node:test";

import { createReview } from "../services/reviewService.js";

test("createReview keeps id server-owned", async () => {
  const review = await createReview({ id: "attacker-controlled", rating: 5 });

  assert.notEqual(review.id, "attacker-controlled");
  assert.match(review.id, /^rev_\d+_[0-9a-f-]{36}$/i);
  assert.equal(review.rating, 5);
});

test("createReview generates unique IDs for same-millisecond reviews", async (t) => {
  const originalNow = Date.now;
  Date.now = () => 1234567890;
  t.after(() => {
    Date.now = originalNow;
  });

  const first = await createReview({ rating: 4 });
  const second = await createReview({ rating: 5 });

  assert.notEqual(first.id, second.id);
  assert.match(first.id, /^rev_1234567890_[0-9a-f-]{36}$/i);
  assert.match(second.id, /^rev_1234567890_[0-9a-f-]{36}$/i);
});
