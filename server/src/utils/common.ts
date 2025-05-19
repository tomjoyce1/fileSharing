export function base64ToBuffer(base64: string): Buffer {
  return Buffer.from(base64, "base64");
}
