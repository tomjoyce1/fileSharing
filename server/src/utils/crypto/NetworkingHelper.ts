import { sign as nodeSign } from "node:crypto";
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa";
import type { KeyBundlePrivate, KeyBundlePublic } from "../schema";
import { ok, err, Result } from "neverthrow";
import { db } from "~/db";
import { usersTable } from "~/db/schema";
import { eq } from "drizzle-orm";
import { deserializeKeyBundlePublic } from "./KeyHelper";
import { appendFileSync, existsSync, writeFileSync } from "node:fs";

export const DEFAULT_BASE_URL = "http://localhost:3000";
const REPLAY_ATTACK_WINDOW_MS = 60 * 1000;
const SIGNATURE_DELIMITER = "||";

type User = typeof usersTable.$inferSelect;

export function createCanonicalRequestString(
  username: string,
  timestamp: string,
  method: string,
  path: string,
  body: string
): string {
  return `${username}|${timestamp}|${method}|${path}|${body}`;
}

//creates signatures for the canonical request string using both pre-quantum and post-quantum keys
export function createSignatures(
  canonicalString: string,
  privateBundle: KeyBundlePrivate
): { preQuantum: string; postQuantum: string } {
  if (!privateBundle?.preQuantum?.identitySigning?.privateKey) {
    throw new Error("Pre-Quantum identitySigning private key is undefined");
  }

  if (!privateBundle?.postQuantum?.identitySigning?.privateKey) {
    throw new Error("Post-Quantum identitySigning private key is undefined");
  }

  const preQuantumSignature = nodeSign(
    null,
    Buffer.from(canonicalString),
    privateBundle.preQuantum.identitySigning.privateKey
  ).toString("base64");

  const postQuantumSignature = Buffer.from(
    ml_dsa87.sign(
      privateBundle.postQuantum.identitySigning.privateKey,
      Buffer.from(canonicalString)
    )
  ).toString("base64");

  return { preQuantum: preQuantumSignature, postQuantum: postQuantumSignature };
}

// parses the combined signature string into pre-quantum and post-quantum signatures
function parseSignatures(
  signature: string
): { preQuantum: string; postQuantum: string } | null {
  const [preQuantum, postQuantum] = signature.split(SIGNATURE_DELIMITER);
  return preQuantum && postQuantum ? { preQuantum, postQuantum } : null;
}

// checks if the request timestamp is within the allowed replay attack window
function isWithinReplayWindow(timestamp: string): boolean {
  const requestTime = new Date(timestamp);
  const now = new Date();
  const timeDiff = Math.abs(now.getTime() - requestTime.getTime());
  return timeDiff <= REPLAY_ATTACK_WINDOW_MS;
}

// verifies the signatures of the canonical request string against the public key bundle
async function verifySignatures(
  canonicalString: string,
  signatures: { preQuantum: string; postQuantum: string },
  publicBundle: KeyBundlePublic
): Promise<boolean> {
  try {
    const { verify } = await import("node:crypto");

    const preQuantumValid = verify(
      null,
      Buffer.from(canonicalString),
      publicBundle.preQuantum.identitySigningPublicKey,
      Buffer.from(signatures.preQuantum, "base64")
    );

    const postQuantumValid = ml_dsa87.verify(
      publicBundle.postQuantum.identitySigningPublicKey,
      Buffer.from(canonicalString),
      Buffer.from(signatures.postQuantum, "base64")
    );

    return preQuantumValid && postQuantumValid;
  } catch {
    return false;
  }
}

// creates the request headers with the necessary authentication information
function createRequestHeaders(
  username: string,
  timestamp: string,
  combinedSignature: string
): Headers {
  return new Headers({
    "Content-Type": "application/json",
    "X-Username": username,
    "X-Timestamp": timestamp,
    "X-Signature": combinedSignature,
  });
}

// creates a signed request with the provided options
async function _createSignedRequest(options: {
  method: string;
  path: string;
  body?: string;
  username: string;
  privateBundle: KeyBundlePrivate;
  baseUrl?: string;
}): Promise<Request> {
  const {
    method,
    path,
    body = "",
    username,
    privateBundle,
    baseUrl = DEFAULT_BASE_URL,
  } = options;

  const url = new URL(path, baseUrl).toString();
  const timestamp = new Date().toISOString();

  const canonicalString = createCanonicalRequestString(
    username,
    timestamp,
    method,
    path,
    body
  );

  const signatures = createSignatures(canonicalString, privateBundle);
  const combinedSignature = `${signatures.preQuantum}${SIGNATURE_DELIMITER}${signatures.postQuantum}`;
  const headers = createRequestHeaders(username, timestamp, combinedSignature);

  return new Request(url, {
    method,
    headers,
    body: body || undefined,
  });
}

// creates a signed POST request with the provided path and request body
export async function createSignedPOST(
  path: string,
  requestBody: any,
  username: string,
  privateBundle: KeyBundlePrivate,
  baseUrl?: string
): Promise<Response> {
  const bodyString =
    typeof requestBody === "string" ? requestBody : JSON.stringify(requestBody);

  const signedRequest = await _createSignedRequest({
    method: "POST",
    path,
    body: bodyString,
    username,
    privateBundle,
    baseUrl,
  });

  return fetch(signedRequest);
}

// creates a signed GET request with the provided path and query parameters
export async function createSignedGET(
  path: string,
  queryParams: Record<string, string> = {},
  username: string,
  privateBundle: KeyBundlePrivate,
  baseUrl?: string
): Promise<Response> {
  const url = new URL(path, baseUrl || DEFAULT_BASE_URL);
  Object.entries(queryParams).forEach(([key, value]) => {
    url.searchParams.set(key, value);
  });

  const signedRequest = await _createSignedRequest({
    method: "GET",
    path: url.pathname + url.search,
    username,
    privateBundle,
    baseUrl,
  });

  return fetch(signedRequest);
}

async function verifyRequestSignature(
  request: Request,
  publicBundle: KeyBundlePublic,
  providedBody?: string
): Promise<string | null> {
  const username = request.headers.get("X-Username");
  const timestamp = request.headers.get("X-Timestamp");
  const signature = request.headers.get("X-Signature");

  if (!username || !timestamp || !signature) {
    return null;
  }

  if (!isWithinReplayWindow(timestamp)) {
    return null;
  }

  const signatures = parseSignatures(signature);
  if (!signatures) {
    return null;
  }
  const requestBody =
    providedBody !== undefined ? providedBody : await request.clone().text();

  const requestUrl = new URL(request.url);
  const requestPath = requestUrl.pathname;

  const canonicalString = createCanonicalRequestString(
    username,
    timestamp,
    request.method,
    requestPath,
    requestBody
  );

  try {
    const isValid = await verifySignatures(
      canonicalString,
      signatures,
      publicBundle
    );
    if (!isValid) {
      return null;
    }
    return username;
  } catch {
    return null;
  }
}

export async function getAuthenticatedUserFromRequest(
  req: Request,
  body?: string
): Promise<Result<User, string>> {
  const username = req.headers.get("X-Username");
  if (!username) {
    return err("Missing username header");
  }

  try {
    const user = await db
      .select()
      .from(usersTable)
      .where(eq(usersTable.username, username))
      .limit(1)
      .then((rows) => rows[0]);

    if (!user) {
      return err("User not found");
    }

    const userPublicBundle = deserializeKeyBundlePublic(
      JSON.parse(user.public_key_bundle.toString())
    );

    const requestBody = body !== undefined ? body : await req.clone().text();

    const authenticatedUsername = await verifyRequestSignature(
      req,
      userPublicBundle,
      requestBody
    );
    if (!authenticatedUsername || authenticatedUsername !== username) {
      return err("Invalid signature");
    }

    return ok(user);
  } catch {
    return err("Authentication failed");
  }
}
