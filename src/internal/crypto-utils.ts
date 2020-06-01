import * as crypto from 'crypto';
import asn1js from 'asn1js';
import {
  GCMParameters,
  IVParameter
} from './jasf4/asn-objects';

type CipherCBCTypes = 'aes-128-cbc' | 'aes-192-cbc' | 'aes-256-cbc';
type CipherCCMTypes = 'aes-128-ccm' | 'aes-192-ccm' | 'aes-256-ccm';
type CipherGCMTypes = 'aes-128-gcm' | 'aes-192-gcm' | 'aes-256-gcm';

export interface ParameterSpecResult {
  iv?: Buffer;
  icvLen?: number;
}

export interface CipherAlgorithm {
  nodeAlgorithm: CipherCBCTypes | CipherCCMTypes | CipherGCMTypes;
  oid: string;
  isGcmMode: boolean;
  createParameterSpec?: (params: { iv: Buffer, icvLen?: number }) => asn1js.LocalValueBlock;
  parseParameterSpec?: (input: asn1js.LocalValueBlock) => ParameterSpecResult;
}

export interface HashAlgorithm {
  nodeAlgorithm: string;
  oid: string;
  digestSize: number;
}

type CipherAttrMap = Record<string, CipherAlgorithm>;
type HashAttrMap = Record<string, HashAlgorithm>;

const gcmParseParameterSpec = (input) => {
  const impl = new GCMParameters({
    schema: input
  });
  return {
    iv: impl.nonce,
    icvLen: impl.icvLen
  };
};

const parseIvParameterSpec = (input) => {
  const impl = new IVParameter({
    schema: input
  });
  return {
    iv: impl.iv
  };
};

const cipherAlgorithms: CipherAlgorithm[] = [
  {
    nodeAlgorithm: 'aes-128-cbc',
    oid: '2.16.840.1.101.3.4.1.2',
    isGcmMode: false,
    createParameterSpec: ({iv, icvLen}) => new IVParameter({
      iv: iv
    }),
    parseParameterSpec: parseIvParameterSpec
  },
  {
    nodeAlgorithm: 'aes-192-cbc',
    oid: '2.16.840.1.101.3.4.1.22',
    isGcmMode: false,
    createParameterSpec: ({iv, icvLen}) => new IVParameter({
      iv: iv
    }),
    parseParameterSpec: parseIvParameterSpec
  },
  {
    nodeAlgorithm: 'aes-256-cbc',
    oid: '2.16.840.1.101.3.4.1.42',
    isGcmMode: false,
    createParameterSpec: ({iv, icvLen}) => new IVParameter({
      iv: iv
    }),
    parseParameterSpec: parseIvParameterSpec
  },
  {
    nodeAlgorithm: 'aes-128-gcm',
    oid: '2.16.840.1.101.3.4.1.6',
    isGcmMode: true,
    createParameterSpec: ({iv, icvLen}) => new GCMParameters({
      nonce: iv,
      icvLen: icvLen ? icvLen : 12
    }),
    parseParameterSpec: gcmParseParameterSpec
  },
  {
    nodeAlgorithm: 'aes-192-gcm',
    oid: '2.16.840.1.101.3.4.1.26',
    isGcmMode: true,
    createParameterSpec: ({iv, icvLen}) => new GCMParameters({
      nonce: iv,
      icvLen: icvLen ? icvLen : 12
    }),
    parseParameterSpec: gcmParseParameterSpec
  },
  {
    nodeAlgorithm: 'aes-256-gcm',
    oid: '2.16.840.1.101.3.4.1.46',
    isGcmMode: true,
    createParameterSpec: ({iv, icvLen}) => new GCMParameters({
      nonce: iv,
      icvLen: icvLen ? icvLen : 12
    }),
    parseParameterSpec: gcmParseParameterSpec
  }
];

const hashAlgorithms: HashAlgorithm[] = [
  {
    nodeAlgorithm: 'sha256',
    oid: '2.16.840.1.101.3.4.2.1',
    digestSize: 32
  },
  {
    nodeAlgorithm: 'sha384',
    oid: '2.16.840.1.101.3.4.2.2',
    digestSize: 48
  },
  {
    nodeAlgorithm: 'sha512',
    oid: '2.16.840.1.101.3.4.2.3',
    digestSize: 64
  },
  {
    nodeAlgorithm: 'sha224',
    oid: '2.16.840.1.101.3.4.2.4',
    digestSize: 28
  },
  // {
  //   nodeAlgorithm: 'sha512-224',
  //   oid: '2.16.840.1.101.3.4.2.5',
  //   digestSize: 28
  // },
  // {
  //   nodeAlgorithm: 'sha512-256',
  //   oid: '2.16.840.1.101.3.4.2.6',
  //   digestSize: 32
  // },
  // {
  //   nodeAlgorithm: 'sha3-224',
  //   oid: '2.16.840.1.101.3.4.2.7',
  //   digestSize: 28
  // },
  // {
  //   nodeAlgorithm: 'sha3-256',
  //   oid: '2.16.840.1.101.3.4.2.8',
  //   digestSize: 32
  // },
  // {
  //   nodeAlgorithm: 'sha3-384',
  //   oid: '2.16.840.1.101.3.4.2.9',
  //   digestSize: 48
  // },
  // {
  //   nodeAlgorithm: 'sha3-512',
  //   oid: '2.16.840.1.101.3.4.2.10',
  //   digestSize: 64
  // },
  // {
  //   nodeAlgorithm: 'shake128',
  //   oid: '2.16.840.1.101.3.4.2.11'
  // },
  // {
  //   nodeAlgorithm: 'shake256',
  //   oid: '2.16.840.1.101.3.4.2.12'
  // },
  // {
  //   nodeAlgorithm: 'hmacWithSHA3-224',
  //   oid: '2.16.840.1.101.3.4.2.13',
  //   digestSize: 28
  // },
  // {
  //   nodeAlgorithm: 'hmacWithSHA3-256',
  //   oid: '2.16.840.1.101.3.4.2.14',
  //   digestSize: 32
  // },
  // {
  //   nodeAlgorithm: 'hmacWithSHA3-384',
  //   oid: '2.16.840.1.101.3.4.2.15',
  //   digestSize: 48
  // },
  // {
  //   nodeAlgorithm: 'hmacWithSHA3-512',
  //   oid: '2.16.840.1.101.3.4.2.15',
  //   digestSize: 64
  // }
];

const cipherOids: CipherAttrMap = Object.freeze(cipherAlgorithms.reduce<CipherAttrMap>((map, item) => {
  map[item.oid] = item;
  return map;
}, {}));

const cipherNodeAlgorithms: CipherAttrMap = Object.freeze(cipherAlgorithms.reduce<CipherAttrMap>((map, item) => {
  map[item.nodeAlgorithm] = item;
  return map;
}, {}));

const hashOids: HashAttrMap = Object.freeze(hashAlgorithms.reduce<HashAttrMap>((map, item) => {
  map[item.oid] = item;
  return map;
}, {}));

const hashNodeAlgorithms: HashAttrMap = Object.freeze(hashAlgorithms.reduce<HashAttrMap>((map, item) => {
  map[item.nodeAlgorithm] = item;
  return map;
}, {}));

export function findCipherByNodeAlgorithm(algo: string): CipherAlgorithm | undefined {
  return cipherNodeAlgorithms[algo];
}

export function findCipherByOid(oid: string): CipherAlgorithm | undefined {
  return cipherOids[oid];
}

export function findHashByNodeAlgorithm(algo: string): HashAlgorithm | undefined {
  return hashNodeAlgorithms[algo];
}

export function findHashByOid(oid: string): HashAlgorithm | undefined {
  return hashOids[oid];
}

export interface ICreateCipherOptions {
  nodeAlgorithm?: string;
  oid?: string;
  key: Buffer;
  iv?: Buffer;
  icvLen?: number;
  parameterSpec?: asn1js.LocalValueBlock;
}

export interface ICreateHashOptions {
  nodeAlgorithm?: string;
  oid?: string;
}

export interface ICreateCipherResult extends CipherAlgorithm {
  createCipher: () => crypto.CipherGCM;
  createDecipher: () => crypto.DecipherGCM;
  parameterSpec?: asn1js.LocalValueBlock;
  icvLen: number | undefined;
}

export interface ICreateHashResult extends HashAlgorithm {
  createHash: () => crypto.Hash;
  createHmac: (key: Buffer) => crypto.Hmac;
}

export function createCipher(options: ICreateCipherOptions): ICreateCipherResult {
  const algorithm: CipherAlgorithm | undefined =
    options.nodeAlgorithm ? findCipherByNodeAlgorithm(options.nodeAlgorithm) :
      options.oid ? findCipherByOid(options.oid) : undefined;
  if (!algorithm) {
    throw new Error('Unknown algorithm');
  }
  const cipherOptions: any = {};
  let iv = options.iv;
  let icvLen: number | undefined = options.icvLen;
  if (options.parameterSpec && algorithm.parseParameterSpec) {
    const result = algorithm.parseParameterSpec(options.parameterSpec);
    iv = result.iv;
    icvLen = result.icvLen || icvLen;
  }
  if (!iv) {
    throw new Error('Need IV');
  }
  const parameterSpec = algorithm.createParameterSpec ?
    algorithm.createParameterSpec({iv, icvLen}) :
    undefined;
  if (parameterSpec) {
    icvLen = (parameterSpec as any).icvLen;
    if (icvLen) {
      cipherOptions.authTagLength = icvLen;
    }
  }
  return {
    ...algorithm,
    //@ts-ignore
    createCipher: () => crypto.createCipheriv(algorithm.nodeAlgorithm, options.key, iv, cipherOptions),
    //@ts-ignore
    createDecipher: () => crypto.createDecipheriv(algorithm.nodeAlgorithm, options.key, iv, cipherOptions),
    parameterSpec: parameterSpec,
    icvLen: icvLen
  };
}

export function createHash(options: ICreateHashOptions): ICreateHashResult {
  const algorithm: HashAlgorithm | undefined =
    options.nodeAlgorithm ? findHashByNodeAlgorithm(options.nodeAlgorithm) :
      options.oid ? findHashByOid(options.oid) : undefined;
  if (!algorithm) {
    throw new Error('Unknown algorithm');
  }
  return {
    ...algorithm,
    createHash: () => crypto.createHash(algorithm.nodeAlgorithm),
    createHmac: (key) => crypto.createHmac(algorithm.nodeAlgorithm, key)
  };
}

export interface IHKDFOptions {
  nodeAlgorithm?: string;
  oid?: string;
  hashFactory?: ICreateHashResult;
  master: Buffer;
  length: number;
  info?: Buffer;
  salt?: Buffer;
}

export interface IHKDFResult extends HashAlgorithm {
  output: Buffer;
  salt: Buffer;
}

export function hkdfCompute(options: IHKDFOptions): IHKDFResult {
  const algorithm = options.hashFactory ?
    options.hashFactory :
    createHash(options);
  const salt = options.salt ? options.salt : crypto.randomBytes(options.length);
  const info = options.info ? options.info : Buffer.alloc(0);

  // RFC5869 Step 1 (Extract)
  const prk = algorithm.createHmac(salt).update(options.master).digest();

  // RFC5869 Step 1 (Expand)
  let t = Buffer.alloc(0);
  const okm = Buffer.alloc(Math.ceil(options.length / algorithm.digestSize) * algorithm.digestSize);
  for (let i=0; i<Math.ceil(options.length / algorithm.digestSize); i++) {
    const concat = Buffer.concat([
      t, info, Buffer.from([i + 1])
    ]);
    t = algorithm.createHmac(prk).update(concat).digest();
    okm.set(t, algorithm.digestSize * i);
  }
  return {
    ...algorithm,
    salt,
    output: okm.slice(0, options.length)
  };
}
