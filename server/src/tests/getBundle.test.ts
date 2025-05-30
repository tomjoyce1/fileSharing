import { expect, test, describe } from "bun:test";
import { serializeKeyBundlePublic } from "~/utils/crypto/KeyHelper";
import { getTestHarness } from "./setup";

describe("Get Bundle API", () => {
  const harness = getTestHarness();

  test("successfully retrieve own key bundle", async () => {
    await harness.createUser("testuser");

    const response = await harness.getUserKeyBundle("testuser", "testuser");
    harness.expectSuccessfulResponse(response);

    const responseData = (await response.json()) as any;
    expect(responseData.key_bundle).toBeDefined();

    const user = harness.getUser("testuser");
    const expectedBundle = serializeKeyBundlePublic(user.keyBundle.public);
    expect(responseData.key_bundle).toEqual(expectedBundle);
  });

  test("retrieve bundle for different user", async () => {
    await harness.createUser("userA");
    await harness.createUser("userB");

    const response = await harness.getUserKeyBundle("userB", "userA");
    harness.expectSuccessfulResponse(response);

    const responseData = (await response.json()) as any;

    const userB = harness.getUser("userB");
    const expectedBundle = serializeKeyBundlePublic(userB.keyBundle.public);
    expect(responseData.key_bundle).toEqual(expectedBundle);

    const userA = harness.getUser("userA");
    const userABundle = serializeKeyBundlePublic(userA.keyBundle.public);
    expect(responseData.key_bundle).not.toEqual(userABundle);
  });

  test("retrieve bundle for invalid/nonexistent user", async () => {
    await harness.createUser("testuser");

    const response = await harness.getUserKeyBundle(
      "nonexistentuser",
      "testuser"
    );
    harness.expectBadRequest(response);

    const responseData = (await response.json()) as any;
    expect(responseData.message).toBe("Invalid username");
  });
});
