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
import {
  CognitoAccessTokenPayload,
  CognitoIdTokenPayload,
} from "./jwt-model.js";
import { MinimalResponse, configure } from "./config.js";

export async function throwIfNot2xx(res: MinimalResponse) {
  if (res.ok) {
    return res;
  }

  const detail = (await res.json()) as { __type: string; message: string };
  let message = detail.message;
  if (detail.__type === "UserLambdaValidationException") {
    const match = detail.message.match(/^.+failed with error (.+)$/);
    if (match) {
      message = match[1];
    }
  }

  // Add more context for rate limiting errors
  if (detail.__type === "TooManyRequestsException") {
    message = `Rate limit exceeded: ${message}. Please wait before retrying.`;
  }

  const err = new Error(message);
  err.name = detail.__type;
  throw err;
}

export function parseJwtPayload<
  T extends CognitoAccessTokenPayload | CognitoIdTokenPayload,
>(jwt: string) {
  const parts = jwt.split(".");
  const payload = parts[1];
  if (!payload) {
    throw new Error("Invalid JWT");
  }
  return JSON.parse(
    new TextDecoder().decode(bufferFromBase64Url(payload))
  ) as T;
}

/**
 * Compute the client clock drift (in ms) at the moment a token is received:
 * the local wall clock minus the access token's server-issued `iat` claim.
 *
 * Positive => the device clock is AHEAD of server time (the case that makes a
 * freshly-issued token look already-expired and forces a logout loop). This is
 * anchored at receipt (when `iat` ≈ server "now"), so it measures the clock
 * offset, not the token's age. Returns 0 when it can't be determined, which
 * preserves the previous (uncorrected) behavior. Mirrors the `clockDrift` that
 * AWS Cognito's CognitoUserSession computes for its `isValid()` check.
 */
export function computeClockDriftMs(accessToken?: string): number {
  if (!accessToken) return 0;
  try {
    const { iat } = parseJwtPayload<CognitoAccessTokenPayload>(accessToken);
    if (typeof iat !== "number" || !Number.isFinite(iat) || iat <= 0) return 0;
    return Date.now() - iat * 1000;
  } catch {
    return 0;
  }
}

/**
 * Maximum length of each setTimeout chunk used by setTimeoutWallClock.
 * Browsers don't reliably credit setTimeout time spent in system sleep,
 * so we never trust a single setTimeout for more than this long, and
 * re-check the wall clock on every chunk boundary.
 */
const WALL_CLOCK_TIMEOUT_CHUNK_MS = 30 * 1000;

/**
 * Poll interval used once the remaining time until the deadline is at most
 * WALL_CLOCK_TIMEOUT_CHUNK_MS. In this final stretch the wall clock is
 * re-checked every second (mirroring the 1-second polling this util has
 * always used near the deadline), so that sleeping through the deadline
 * delays the callback by at most ~1 second after wake, instead of by the
 * full remainder of one uncredited setTimeout
 */
const WALL_CLOCK_FINAL_POLL_MS = 1000;

/**
 * Schedule a callback once, like setTimeout, but count
 * time spent sleeping also as time spent. This is done by tracking a
 * wall-clock deadline and chaining short setTimeouts (at most 30 seconds
 * each, at most 1 second each during the final 30 seconds) that re-check
 * the wall clock upon every wake, and only run the callback when the
 * wall-clock deadline has truly passed. This way, if the device sleeps past
 * the deadline, the callback runs within one chunk (at most 30 seconds,
 * typically much sooner) after waking, instead of waiting out the
 * remainder of one long setTimeout
 */
export function setTimeoutWallClock<T>(cb: () => T, ms: number) {
  const executeAt = Date.now() + ms;
  let timer: ReturnType<typeof setTimeout>;
  let cancelled = false;

  const scheduleNextCheck = () => {
    const remaining = executeAt - Date.now();
    // Cap every setTimeout: long remainders are chunked at 30 seconds, and
    // the final stretch is polled at 1 second, so device sleep is always
    // detected at the next chunk boundary. Delays shorter than the poll
    // interval are scheduled as-is (e.g. 500 ms fires after 500 ms)
    const delay =
      remaining > WALL_CLOCK_TIMEOUT_CHUNK_MS
        ? WALL_CLOCK_TIMEOUT_CHUNK_MS
        : Math.min(Math.max(remaining, 0), WALL_CLOCK_FINAL_POLL_MS);
    timer = setTimeout(() => {
      if (cancelled) return;
      if (Date.now() >= executeAt) {
        cb();
      } else {
        scheduleNextCheck();
      }
    }, delay);

    // unref the timer if we can, so that e.g. when running in Node.js
    // this timer would not block program exit:
    if (typeof timer.unref === "function") timer.unref();
  };
  scheduleNextCheck();

  return () => {
    cancelled = true;
    clearTimeout(timer);
  };
}

export function currentBrowserLocationWithoutFragmentIdentifier() {
  const { location } = configure();
  const current = new URL(location.href);
  current.hash = "";
  return current.href;
}

export function removeFragmentIdentifierFromBrowserLocation() {
  const { history } = configure();
  history.pushState("", "", currentBrowserLocationWithoutFragmentIdentifier());
}

export function timeAgo(now: Date, historicDate?: Date) {
  if (!historicDate) return;
  const ranges = {
    years: 3600 * 24 * 365,
    months: 3600 * 24 * 30,
    weeks: 3600 * 24 * 7,
    days: 3600 * 24,
    hours: 3600,
    minutes: 60,
  };
  const secondsElapsed = Math.max(
    (now.valueOf() - historicDate.valueOf()) / 1000,
    0
  );
  const [unit, range] = Object.entries(ranges).find(([, range]) => {
    return range < secondsElapsed;
  }) ?? ["seconds", 1];
  const delta = secondsElapsed / range;
  return unit === "seconds" && delta < 10
    ? "Just now"
    : new Intl.RelativeTimeFormat("en").format(
        -Math.floor(delta),
        unit as Intl.RelativeTimeFormatUnit
      );
}

/**
 * Base64 implementations below as atob and btoa don't work with unicode
 * and aren't available in all JS environments to begin with, e.g. React Native
 */

const _bufferFromBase64 = function (characters: string, padChar = "") {
  const map = characters
    .split("")
    .reduce(
      (acc, char, index) => Object.assign(acc, { [char.charCodeAt(0)]: index }),
      {} as { [key: number]: number }
    );
  return function (base64: string) {
    const paddingLength = padChar
      ? // eslint-disable-next-line security/detect-non-literal-regexp
        base64.match(new RegExp(`^.+?(${padChar}?${padChar}?)$`))![1].length
      : 0;
    let first: number, second: number, third: number, fourth: number;
    return base64.match(/.{1,4}/g)!.reduce(
      (acc, chunk, index) => {
        first = map[chunk.charCodeAt(0)];
        second = map[chunk.charCodeAt(1)];
        third = map[chunk.charCodeAt(2)];
        fourth = map[chunk.charCodeAt(3)];
        acc[3 * index] = (first << 2) | (second >> 4);
        acc[3 * index + 1] = ((second & 0b1111) << 4) | (third >> 2);
        acc[3 * index + 2] = ((third & 0b11) << 6) | fourth;
        return acc;
      },
      new Uint8Array((base64.length * 3) / 4 - paddingLength)
    );
  };
};

export const bufferFromBase64 = _bufferFromBase64(
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
  "="
);
export const bufferFromBase64Url = _bufferFromBase64(
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
);

const _bufferToBase64 = function (characters: string, padChar = "") {
  const map = characters
    .split("")
    .reduce(
      (acc, char, index) => Object.assign(acc, { [index]: char }),
      {} as { [key: number]: string }
    );
  return function (base64: ArrayBuffer) {
    const result = [] as string[];
    for (const chunk of chunks(new Uint8Array(base64), 3)) {
      result.push(map[chunk[0] >> 2]);
      result.push(map[((chunk[0] & 0b11) << 4) | (chunk[1] >> 4)]);
      result.push(
        chunk[1] !== undefined
          ? map[((chunk[1] & 0b1111) << 2) | (chunk[2] >> 6)]
          : padChar
      );
      result.push(chunk[2] !== undefined ? map[chunk[2] & 0b111111] : padChar);
    }
    return result.join("");
  };
};

export const bufferToBase64 = _bufferToBase64(
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
  "="
);
export const bufferToBase64Url = _bufferToBase64(
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
);

function* chunks(arr: Uint8Array, n: number): Generator<Uint8Array, void> {
  for (let i = 0; i < arr.length; i += n) {
    yield arr.subarray(i, i + n);
  }
}
