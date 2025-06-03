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

export function createSignatures(
  canonicalString: string,
  privateBundle: KeyBundlePrivate
): { preQuantum: string; postQuantum: string } {
  // Debugging: Log the structure of privateBundle
  console.log("[Debug] Private Key Bundle:", {
    preQuantum: privateBundle?.preQuantum?.identitySigning,
    postQuantum: privateBundle?.postQuantum?.identitySigning,
  });

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

function parseSignatures(
  signature: string
): { preQuantum: string; postQuantum: string } | null {
  const [preQuantum, postQuantum] = signature.split(SIGNATURE_DELIMITER);
  return preQuantum && postQuantum ? { preQuantum, postQuantum } : null;
}

function isWithinReplayWindow(timestamp: string): boolean {
  const requestTime = new Date(timestamp);
  const now = new Date();
  const timeDiff = Math.abs(now.getTime() - requestTime.getTime());
  return timeDiff <= REPLAY_ATTACK_WINDOW_MS;
}

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

    console.log("Backend Canonical:", canonicalString);

    return preQuantumValid && postQuantumValid;
  } catch {
    return false;
  }
}

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

function logSigDebug(label: string, data: any) {
  try {
    const logFilePath = "sig-debug.log";
    if (!existsSync(logFilePath)) {
      writeFileSync(logFilePath, "", { flag: "w" });
    }
    appendFileSync(
      logFilePath,
      `[${new Date().toISOString()}] ${label}: ${
        typeof data === "string" ? data : JSON.stringify(data, null, 2)
      }\n`
    );
  } catch (e) {
    console.error("[sig-debug.log] Failed to write log", e);
  }
}

async function verifyRequestSignature(
  request: Request,
  publicBundle: KeyBundlePublic,
  providedBody?: string
): Promise<string | null> {
  const username = request.headers.get("X-Username");
  const timestamp = request.headers.get("X-Timestamp");
  const signature = request.headers.get("X-Signature");

  console.log("Starting verifyRequestSignature...");

  console.log(
    "new log Key type:",
    typeof publicBundle.postQuantum.identitySigningPublicKey,
    "new log Length:",
    publicBundle.postQuantum.identitySigningPublicKey.length
  );

  console.log("new log Username:", request.headers.get("X-Username"));
  console.log("new log Timestamp:", request.headers.get("X-Timestamp"));
  console.log("new log Body:", request.headers.get("X-Signature"));

  console.log("AUTH REQUEST HEADERS", { username, timestamp, signature });

  if (!username || !timestamp || !signature) {
    console.log("AUTH ERROR", "Missing required headers");
    return null;
  }

  if (!isWithinReplayWindow(timestamp)) {
    console.log("AUTH ERROR", {
      serverTime: new Date().toISOString(),
      clientTimestamp: timestamp,
    });
    return null;
  }

  const signatures = parseSignatures(signature);
  if (!signatures) {
    console.log("AUTH ERROR", "Invalid signature format");
    return null;
  }

  const requestBody =
    providedBody !== undefined ? providedBody : await request.clone().text();

  console.log("AUTH REQUEST BODY", requestBody);

  const requestUrl = new URL(request.url);
  const requestPath = requestUrl.pathname;

  const canonicalString = createCanonicalRequestString(
    username,
    timestamp,
    request.method,
    requestPath,
    requestBody
  );

  console.log("AUTH BACKEND CANONICAL STRING", canonicalString);
  console.log("AUTH SIGNATURES", signatures);

  try {
    const isValid = await verifySignatures(
      canonicalString,
      signatures,
      publicBundle
    );
    console.log("AUTH SIGNATURE VERIFICATION RESULT", isValid);
    console.log("new log isValid:", isValid);
    if (!isValid) {
      console.log("new log isValid:", isValid);
      console.log("AUTH SIGNATURE VERIFICATION FAILURE", {
        canonicalString,
        signatures,
      });
      return null;
    }
    return username;
  } catch (e) {
    console.log("new log e:", e);
    console.log(
      "AUTH SIGNATURE VERIFICATION EXCEPTION",
      e instanceof Error ? e.stack || e.message : e
    );
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
    // get user from database
    const user = await db
      .select()
      .from(usersTable)
      .where(eq(usersTable.username, username))
      .limit(1)
      .then((rows) => rows[0]);

    if (!user) {
      return err("User not found");
    }

    // verify request signature
    const userPublicBundle = deserializeKeyBundlePublic(
      JSON.parse(user.public_key_bundle.toString())
    );

    // Log public key bundle for debugging
    console.log("[Debug] Public Key Bundle:", {
      preQuantum: {
        identityKemPublicKey: userPublicBundle.preQuantum.identityKemPublicKey
          .export({ format: "der", type: "spki" })
          .toString("base64"),
        identitySigningPublicKey:
          userPublicBundle.preQuantum.identitySigningPublicKey
            .export({ format: "der", type: "spki" })
            .toString("base64"),
      },
      postQuantum: {
        identitySigningPublicKey:
          userPublicBundle.postQuantum.identitySigningPublicKey
            .slice(0, 10)
            .toString() + "...", // Shortened for brevity
      },
    });

    // use provided body or read from request
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
