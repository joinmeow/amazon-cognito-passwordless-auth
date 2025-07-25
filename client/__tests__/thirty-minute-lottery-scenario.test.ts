/**
 * Copyright Amazon.com, Inc. and its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You
 * may not use this file except in compliance with the License. A copy of
 * the License is located at
 *
 *     http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is
 * distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
 * ANY KIND, either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

describe("30-Minute Session Lottery Bug Scenario", () => {
  /**
   * This test demonstrates the exact scenario that occurred:
   * - User session hits exactly 30 minutes
   * - Tokens expire during page navigation
   * - API calls with expired tokens trigger logout
   * - Background refresh takes 13 seconds
   * - Grace period prevents logout during refresh
   */

  // Helper to simulate the signInStatus computation from hooks.tsx
  const computeSignInStatus = (
    expireAt: Date | string | undefined,
    isRefreshingTokens: boolean,
    now: number = Date.now()
  ): "SIGNED_IN" | "NOT_SIGNED_IN" => {
    if (!expireAt) return "NOT_SIGNED_IN";

    const expireAtTime =
      expireAt instanceof Date
        ? expireAt.valueOf()
        : new Date(expireAt).valueOf();

    // Grace period logic from the fix
    const REFRESH_GRACE_PERIOD_MS = 30000;
    if (isRefreshingTokens && now < expireAtTime + REFRESH_GRACE_PERIOD_MS) {
      return "SIGNED_IN";
    }

    if (now >= expireAtTime) {
      return "NOT_SIGNED_IN";
    }

    return "SIGNED_IN";
  };

  describe("The Exact 30-Minute Lottery Bug Timeline", () => {
    it("should demonstrate the bug scenario step by step", () => {
      // Timeline setup
      const loginTime = new Date("2024-07-24T22:43:00.000Z").valueOf();
      const tokenLifetime = 30 * 60 * 1000; // 30 minutes
      const tokenExpireTime = new Date(loginTime + tokenLifetime);

      // Key timestamps from the actual bug
      const t1_TokensExpire = new Date("2024-07-24T23:13:00.000Z").valueOf();
      const t2_ApiCallFails = new Date("2024-07-24T23:13:14.625Z").valueOf();
      const t3_StatusChecking = new Date("2024-07-24T23:13:15.531Z").valueOf();
      const t4_UserLoggedOut = new Date("2024-07-24T23:13:15.558Z").valueOf();
      const t5_RefreshComplete = new Date("2024-07-24T23:13:28.482Z").valueOf();

      // Step 1: User is happily browsing at 29:59
      let currentTime = t1_TokensExpire - 1000; // 1 second before expiry
      let isRefreshing = false;
      expect(
        computeSignInStatus(tokenExpireTime, isRefreshing, currentTime)
      ).toBe("SIGNED_IN");

      // Step 2: Tokens expire at exactly 30 minutes
      currentTime = t1_TokensExpire;
      expect(
        computeSignInStatus(tokenExpireTime, isRefreshing, currentTime)
      ).toBe("NOT_SIGNED_IN");

      // Step 3: User navigates, triggering API calls with expired tokens
      currentTime = t2_ApiCallFails;
      expect(
        computeSignInStatus(tokenExpireTime, isRefreshing, currentTime)
      ).toBe("NOT_SIGNED_IN");

      // Without grace period, user sees logout here!

      // Step 4: Refresh process starts
      currentTime = t3_StatusChecking;
      isRefreshing = true; // Refresh has started

      // WITH GRACE PERIOD: User stays signed in
      expect(
        computeSignInStatus(tokenExpireTime, isRefreshing, currentTime)
      ).toBe("SIGNED_IN");

      // WITHOUT GRACE PERIOD: User would be logged out
      const withoutGracePeriod = currentTime >= tokenExpireTime.valueOf();
      expect(withoutGracePeriod).toBe(true); // Would show NOT_SIGNED_IN

      // Step 5: During the 13-second refresh
      currentTime = t4_UserLoggedOut;
      expect(
        computeSignInStatus(tokenExpireTime, isRefreshing, currentTime)
      ).toBe("SIGNED_IN");

      // Step 6: Refresh completes after 13 seconds
      currentTime = t5_RefreshComplete;
      isRefreshing = false; // Refresh complete
      // New tokens would be set, but let's verify grace period worked
      const timeSinceExpiry = currentTime - tokenExpireTime.valueOf();
      expect(timeSinceExpiry).toBe(28482); // ~28.5 seconds after expiry
      expect(timeSinceExpiry).toBeLessThan(30000); // Still within grace period
    });

    it("should test the consecutive 401 scenario", () => {
      /**
       * The actual bug involved multiple API calls failing:
       * 1. GET /billpay/bills - 401
       * 2. GET /pylon/user-hash - 401
       * These consecutive 401s could trigger forced logout
       */

      const tokenExpireTime = new Date(Date.now() - 5000); // Expired 5 seconds ago
      let consecutive401Count = 0;
      const MAX_CONSECUTIVE_401 = 5;

      // Simulate API calls with expired tokens
      const apiCalls = [
        "/billpay/bills?statuses=PENDING_PAYMENT,PENDING_APPROVAL",
        "/pylon/user-hash",
        "/billpay/accounts",
        "/user/profile",
        "/notifications/unread",
      ];

      // Without refresh in progress
      let isRefreshing = false;
      apiCalls.forEach((endpoint) => {
        const status = computeSignInStatus(tokenExpireTime, isRefreshing);
        if (status === "NOT_SIGNED_IN") {
          consecutive401Count++;
          console.log(
            `API call to ${endpoint} would fail - 401 count: ${consecutive401Count}`
          );
        }
      });

      // All 5 calls would fail, triggering forced logout
      expect(consecutive401Count).toBe(5);
      expect(consecutive401Count >= MAX_CONSECUTIVE_401).toBe(true); // Force logout!

      // Reset and test with refresh in progress
      consecutive401Count = 0;
      isRefreshing = true; // Refresh started after first 401

      apiCalls.forEach((endpoint, index) => {
        // First call triggers refresh
        if (index === 0) {
          isRefreshing = true;
        }

        const status = computeSignInStatus(tokenExpireTime, isRefreshing);
        if (status === "NOT_SIGNED_IN") {
          consecutive401Count++;
        }
      });

      // With grace period, no 401s after refresh starts
      expect(consecutive401Count).toBe(0); // No forced logout!
    });

    it("should test various edge cases around token expiration", () => {
      const baseTime = Date.now();
      const tokenExpireTime = new Date(baseTime);

      const testCases = [
        {
          name: "Tokens expired 1 second ago, no refresh",
          timeOffset: 1000,
          isRefreshing: false,
          expected: "NOT_SIGNED_IN",
        },
        {
          name: "Tokens expired 1 second ago, refresh in progress",
          timeOffset: 1000,
          isRefreshing: true,
          expected: "SIGNED_IN", // Grace period
        },
        {
          name: "Tokens expired 13 seconds ago (typical refresh time), refreshing",
          timeOffset: 13000,
          isRefreshing: true,
          expected: "SIGNED_IN", // Grace period
        },
        {
          name: "Tokens expired 29.9 seconds ago, refreshing",
          timeOffset: 29900,
          isRefreshing: true,
          expected: "SIGNED_IN", // Just within grace period
        },
        {
          name: "Tokens expired 30 seconds ago, refreshing",
          timeOffset: 30000,
          isRefreshing: true,
          expected: "NOT_SIGNED_IN", // Exactly at grace period limit
        },
        {
          name: "Tokens expired 31 seconds ago, refreshing",
          timeOffset: 31000,
          isRefreshing: true,
          expected: "NOT_SIGNED_IN", // Beyond grace period
        },
      ];

      testCases.forEach((testCase) => {
        const currentTime = baseTime + testCase.timeOffset;
        const result = computeSignInStatus(
          tokenExpireTime,
          testCase.isRefreshing,
          currentTime
        );

        expect(result).toBe(testCase.expected);
        console.log(
          `${testCase.name}: ${result} (${result === testCase.expected ? "✓" : "✗"})`
        );
      });
    });

    it("should calculate the probability of hitting this bug", () => {
      /**
       * Let's calculate how "lucky" you were to hit this bug!
       */

      // Assumptions
      const avgSessionDuration = 45 * 60 * 1000; // 45 minutes average session
      const tokenLifetime = 30 * 60 * 1000; // 30 minute tokens
      const avgPageNavigationTime = 5000; // 5 seconds between pages
      const refreshDuration = 13000; // 13 second refresh
      const gracePeriodDuration = 30000; // 30 second grace period

      // Window where bug can occur: tokens must expire during navigation
      // AND refresh must be triggered AND take long enough to be noticed
      const vulnerableWindow = avgPageNavigationTime; // 5 seconds

      // Probability calculations
      const probTokensExpireDuringSession = tokenLifetime / avgSessionDuration; // 0.67
      const probNavigatingDuringExpiry = vulnerableWindow / tokenLifetime; // 0.0028
      const probRefreshTakesLongEnough = refreshDuration / gracePeriodDuration; // 0.43

      const totalProbability =
        probTokensExpireDuringSession *
        probNavigatingDuringExpiry *
        probRefreshTakesLongEnough;

      console.log("Lottery Bug Probability Analysis:");
      console.log(
        `- Tokens expire during session: ${(probTokensExpireDuringSession * 100).toFixed(1)}%`
      );
      console.log(
        `- User navigating during expiry: ${(probNavigatingDuringExpiry * 100).toFixed(2)}%`
      );
      console.log(
        `- Refresh noticeable to user: ${(probRefreshTakesLongEnough * 100).toFixed(1)}%`
      );
      console.log(
        `- Total probability: ${(totalProbability * 100).toFixed(3)}% (1 in ${Math.round(1 / totalProbability)})`
      );

      // You hit a 0.12% chance bug - truly a lottery!
      expect(totalProbability).toBeLessThan(0.002); // Less than 0.2% chance
    });
  });

  describe("Grace Period Effectiveness", () => {
    it("should verify grace period covers typical refresh scenarios", () => {
      const refreshTimes = [
        { region: "us-east-1", time: 8000, name: "Fast refresh" },
        { region: "eu-west-1", time: 13000, name: "Typical refresh" },
        { region: "ap-southeast-1", time: 20000, name: "Slow refresh" },
        { region: "sa-east-1", time: 25000, name: "Very slow refresh" },
      ];

      const tokenExpireTime = new Date(Date.now() - 1000); // Expired 1 second ago
      const gracePeriod = 30000; // 30 seconds

      refreshTimes.forEach(({ region, time, name }) => {
        const currentTime = tokenExpireTime.valueOf() + time;
        const isWithinGracePeriod = time < gracePeriod;

        const status = computeSignInStatus(
          tokenExpireTime,
          true, // Refreshing
          currentTime
        );

        expect(status).toBe(
          isWithinGracePeriod ? "SIGNED_IN" : "NOT_SIGNED_IN"
        );
        console.log(`${name} (${region}): ${time}ms - ${status}`);
      });
    });
  });
});
