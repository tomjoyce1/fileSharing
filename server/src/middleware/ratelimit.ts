import type { Middleware, BurgerRequest, BurgerNext } from "burger-api";

interface RateLimitOptions {
  windowMs: number; // time window in milliseconds
  maxRequests: number; // max requests per window
  skipSuccessfulRequests?: boolean; // only count failed requests
  message?: string; // custom error message
}

// in-memory store for rate limiting - simple dictionary of IP -> timestamps
const ipRequestStore: Record<string, number[]> = {};

const RATELIMIT_CONFIG: RateLimitOptions = {
  windowMs: 1 * 1000,
  maxRequests: 5,
  message: "Too many requests from this IP, please try again later.",
};

// cleanup old entries periodically to prevent memory leaks
setInterval(() => {
  const cutoff = Date.now() - RATELIMIT_CONFIG.windowMs;

  for (const ip in ipRequestStore) {
    // filter out old timestamps
    ipRequestStore[ip] = ipRequestStore[ip]!.filter(
      (timestamp) => timestamp > cutoff
    );

    // remove IPs with no recent requests
    if (ipRequestStore[ip].length === 0) {
      delete ipRequestStore[ip];
    }
  }
}, RATELIMIT_CONFIG.windowMs);

// utility function to get client IP from request headers
function getClientIP(req: BurgerRequest): string | null {
  const xForwardedFor = req.headers.get("x-forwarded-for");
  if (xForwardedFor) {
    return xForwardedFor.split(",")[0].trim();
  }
  return null;
}

export const rateLimit: Middleware = (
  req: BurgerRequest
): BurgerNext | Response => {
  const clientIP = getClientIP(req);
  if (!clientIP) {
    return undefined;
  }

  const now = Date.now();
  const windowStart = now - RATELIMIT_CONFIG.windowMs;

  // initialize or get existing timestamps for this IP
  if (!ipRequestStore[clientIP]) {
    ipRequestStore[clientIP] = [];
  }

  // clean up old timestamps for this IP
  ipRequestStore[clientIP] = ipRequestStore[clientIP].filter(
    (timestamp) => timestamp > windowStart
  );

  // check if limit exceeded
  if (ipRequestStore[clientIP].length >= RATELIMIT_CONFIG.maxRequests) {
    return new Response(
      JSON.stringify({
        message: RATELIMIT_CONFIG.message,
      }),
      {
        status: 429,
        headers: {
          "Content-Type": "application/json",
          "Retry-After": Math.ceil(RATELIMIT_CONFIG.windowMs / 1000).toString(),
          "X-RateLimit-Limit": RATELIMIT_CONFIG.maxRequests.toString(),
          "X-RateLimit-Remaining": "0",
          "X-RateLimit-Reset": new Date(
            now + RATELIMIT_CONFIG.windowMs
          ).toISOString(),
        },
      }
    );
  }

  // Add current request timestamp
  ipRequestStore[clientIP].push(now);

  // continue to next middleware/handler
  return undefined;
};
