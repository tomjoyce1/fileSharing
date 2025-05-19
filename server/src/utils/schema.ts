import { z } from "zod";

export const Username = z
  .string()
  .min(3, "Username must be 3-50 characters")
  .max(50)
  .regex(
    /^[a-zA-Z0-9_]+$/,
    "Username must contain only letters, numbers, and underscores"
  );

export const Password = z
  .string()
  .min(8, "Password must be at least 8 characters")
  .max(256, "Password must be less than 256 characters");

export const HexString = z
  .string()
  .regex(/^[0-9a-fA-F]+$/, "Must be a hex string");

export const Base64String = z
  .string()
  .regex(
    /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/,
    "Must be a Base64 string"
  );
