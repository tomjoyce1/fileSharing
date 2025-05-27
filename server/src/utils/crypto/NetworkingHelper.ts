import { sign as nodeSign } from "node:crypto";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa";
import type { KeyBundlePrivate, KeyBundlePublic } from "../schema";

const DEFAULT_BASE_URL = "http://localhost:3000";
const REPLAY_ATTACK_WINDOW_MS = 60 * 1000;
const SIGNATURE_DELIMITER = "||";

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
  const canonicalRequestString = `${username}|${timestamp}|${method}|${url}|${body}`;

  const preQuantumSignature = nodeSign(
    null,
    Buffer.from(canonicalRequestString),
    privateBundle.preQuantum.identitySigning.privateKey
  ).toString("base64");

  const postQuantumSignature = Buffer.from(
    ml_dsa65.sign(
      Buffer.from(canonicalRequestString),
      privateBundle.postQuantum.identitySigning.privateKey
    )
  ).toString("base64");

  const combinedSignature = `${preQuantumSignature}${SIGNATURE_DELIMITER}${postQuantumSignature}`;

  const headers = new Headers({
    "Content-Type": "application/json",
    "X-Username": username,
    "X-Timestamp": timestamp,
    "X-Signature": combinedSignature,
  });

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

export async function verifyRequestSignature(
  request: Request,
  publicBundle: KeyBundlePublic
): Promise<string | null> {
  const username = request.headers.get("X-Username");
  const timestamp = request.headers.get("X-Timestamp");
  const signature = request.headers.get("X-Signature");

  if (!username || !timestamp || !signature) {
    return null;
  }

  const requestTime = new Date(timestamp);
  const now = new Date();
  const timeDiff = Math.abs(now.getTime() - requestTime.getTime());

  if (timeDiff > REPLAY_ATTACK_WINDOW_MS) {
    return null;
  }

  const clonedRequest = request.clone();
  const requestBody = await clonedRequest.text();

  const canonicalRequestString = `${username}|${timestamp}|${request.method}|${request.url}|${requestBody}`;

  const [preQuantumSignature, postQuantumSignature] =
    signature.split(SIGNATURE_DELIMITER);

  if (!preQuantumSignature || !postQuantumSignature) {
    return null;
  }

  try {
    const { verify } = await import("node:crypto");
    const preQuantumValid = verify(
      null,
      Buffer.from(canonicalRequestString),
      publicBundle.preQuantum.identitySigningPublicKey,
      Buffer.from(preQuantumSignature, "base64")
    );

    const postQuantumValid = ml_dsa65.verify(
      Buffer.from(postQuantumSignature, "base64"),
      Buffer.from(canonicalRequestString),
      publicBundle.postQuantum.identitySigningPublicKey
    );

    return preQuantumValid && postQuantumValid ? username : null;
  } catch (error) {
    return null;
  }
}
