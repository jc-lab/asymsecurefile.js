import crypto from 'crypto';
import * as asn1js from 'asn1js';
import {
  arrayBufferToBuffer
} from '../asn-utils';
import {
  Asn1AuthKeyCheckChunk
} from './asn-objects';
import PBKDF2Params from 'pkijs/build/PBKDF2Params';
import AlgorithmIdentifier from 'pkijs/build/AlgorithmIdentifier';

export const FORMAT_VERSION: number = 4;

export function makeAuthKeyCheck(key: Buffer): Asn1AuthKeyCheckChunk {
  const saltBuffer = crypto.randomBytes(16);
  const params = new PBKDF2Params({
    salt: new asn1js.OctetString({ valueHex: saltBuffer }),
    iterationCount: 4000,
    prf: new AlgorithmIdentifier({
      algorithmId: '1.2.840.113549.2.9', // hmacSha256
      algorithmParams: new asn1js.Null()
    })
  });
  const dfkey = crypto.pbkdf2Sync(key, saltBuffer, 4000, 256, 'sha256');
  return Asn1AuthKeyCheckChunk.create(
    params.toSchema(), dfkey
  );
}

export function checkAuthKey(chunk: Asn1AuthKeyCheckChunk, key: Buffer): boolean {
  const params = new PBKDF2Params({
    schema: chunk.params
  });
  const saltBuffer = arrayBufferToBuffer(params.salt.valueBlock.valueHex);
  const dfkey = crypto.pbkdf2Sync(key, saltBuffer, params.iterationCount, 256, 'sha256');
  const targetKey = arrayBufferToBuffer(chunk.key.valueBlock.valueHex);
  return targetKey.compare(dfkey) === 0;
}
