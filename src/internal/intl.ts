import * as crypto from 'crypto';
import * as cc from 'commons-crypto';

import {
  OperationType
} from '../common';

export enum ParseResult {
  DONE = 0,
  NEED_MORE = 1,
  RERUN = 2,
}

export interface IExactWriterParams {
  operationType: OperationType;
  excludeHeader: boolean;
  version: number;
  authKey: Buffer;
  key: cc.AsymmetricKeyObject;
  tsaLocation?: string;
}

export const JASF_FILE_HEADER = Buffer.from([0x0a,0x9b,0xd8,0x13,0x97,0x1f,0x93,0xe8,0x6b,0x7e,0xdf,0x05,0x70,0x54,0x02]);

function createZeroBuffer(length: number): Buffer {
  const arr: number[] = [];
  for (let i=0; i<length; i++) {
    arr.push(0);
  }
  return Buffer.from(arr);
}

const hashLengthMap: Record<string, number> = {};

function getHashLength(algorithm: string): number {
  if (hashLengthMap[algorithm]) {
    return hashLengthMap[algorithm];
  } else {
    const hash = crypto.createHash(algorithm);
    const length = hash.digest().byteLength;
    hashLengthMap[algorithm] = length;
    return length;
  }
}

function hmacCompute(algorithm: string, key: Buffer, data: Buffer): Buffer {
  return crypto.createHmac(algorithm, key).update(data).digest();
}

/**
 * Naive implementation of RFC5869 in PureJavaScript
 * @param {Buffer} master - Master secret to derive the key.
 * @param {String} hashAlgorithm - Name of hash algorithm used to derive the key.
 * @param {Number} length - Intended length of derived key.
 * @param {String} info - String for information field of HKDF.
 * @param {Buffer} salt - Byte array of salt.
 * @return {Buffer} - Derived key.
 */
export function rfc5869(
  master: Buffer,
  hashAlgorithm: string,
  length: number,
  info?: Buffer,
  salt?: Buffer): Buffer {
  const hashLength = getHashLength(hashAlgorithm);
  const hmacSalt: Buffer = salt ? salt : createZeroBuffer(hashLength);
  const infoBuffer = info ? info : Buffer.alloc(0);
  const prk = hmacCompute(hashAlgorithm, hmacSalt, master);

  // RFC5869 Step 2 (Expand)
  let t = Buffer.alloc(0);
  const okm = Buffer.alloc(Math.ceil(length / hashLength) * hashLength);
  for (let i = 0; i < Math.ceil(length / hashLength); i++) {
    const concat = Buffer.concat([
      t, infoBuffer, Buffer.from([i + 1])
    ]);
    t = hmacCompute(hashAlgorithm, prk, concat);
    okm.set(t, hashLength * i);
  }
  return okm.slice(0, length);
}
