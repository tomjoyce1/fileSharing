declare module "argon2-browser" {
  interface Argon2Params {
    pass: string;
    salt: string;
    type: number;
    hashLen: number;
    time: number;
    mem: number;
    parallelism: number;
    raw: boolean;
  }

  interface Argon2Result {
    hash: Uint8Array;
  }

  enum ArgonType {
    Argon2d = 0,
    Argon2i = 1,
    Argon2id = 2,
  }

  function hash(params: Argon2Params): Promise<Argon2Result>;

  export default {
    hash,
    ArgonType,
  };
}
