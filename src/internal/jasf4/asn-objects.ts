import * as asn1js from 'asn1js';
import {
  arrayBufferToBuffer,
  bufferToArrayBuffer,
  copyToAsn1ObjectIdentifier,
  copyToAsn1OctetString
} from '../asn-utils';
import AlgorithmIdentifier from 'pkijs/build/AlgorithmIdentifier';
import PublicKeyInfo from 'pkijs/build/PublicKeyInfo';
import * as cc from 'commons-crypto';
import {
  addChunkType
} from './chunk-resolver';

export enum ChunkIds {
  DefaultHeader = 0x01,
  AuthKeyCheckData = 0x02,
  AsymAlgorithmIdentifier = 0x21,
  DataCryptoAlgorithmParameterSpec = 0x31,
  DataMacAlgorithm = 0x32,
  EphemeralECPublicKey = 0x33,
  DataKeyInfo = 0x34,
  EncryptedDataKeyInfo = 0x35,
  DHCheckData = 0x39,
  Data = 0x70,
  MacOfEncryptedData = 0x72,
  Fingerprint = 0x76,
  SignedFingerprint = 0x77,
  Timestamp = 0x79,
  CustomBegin = 0x80
}

export interface IAsn1LocalValueable {
  toJSON(): asn1js.JsonLocalBaseBlock;
}

export interface IAsn1BaseObject extends IAsn1LocalValueable {
  toBER(sizeOnly?: boolean): ArrayBuffer;
}

export abstract class Asn1BaseObject implements IAsn1BaseObject {
  public abstract toJSON(): asn1js.JsonLocalBaseBlock;
  public abstract toBER(sizeOnly?: boolean): ArrayBuffer;
}

export abstract class Asn1BaseChunk implements IAsn1BaseObject {
  public abstract toJSON(): asn1js.JsonLocalBaseBlock;
  public abstract toBER(sizeOnly?: boolean): ArrayBuffer;
}

function makeChunkSchema(dataClass: any, name?: string) {
  const dataSchema = dataClass.DATA_SCHEMA || new dataClass({
    name: 'data'
  });
  return new asn1js.Sequence({
    name: name,
    primitiveSchema: [
      new asn1js.Integer({
        name: 'id'
      }),
      new asn1js.Integer({
        name: 'flags'
      }),
      dataSchema
    ]
  });
}

function registerSymbol(o: any, symbol: symbol) {
  Object.defineProperty(o, S_Asn1EncryptedChunk, {
    value: true
  });
}

function checkSymbol(o: any, symbol: symbol) {
  return symbol in o;
}

function toNumber(value: number | asn1js.Integer): number {
  if (typeof value === 'number') {
    return value;
  }
  return value.valueBlock.valueDec;
}

function toBuffer(value: Buffer | asn1js.OctetString): Buffer {
  if (Buffer.isBuffer(value)) {
    return value;
  }
  return arrayBufferToBuffer(value.valueBlock.valueHex);
}

function toAsnOctetString(value: Buffer | asn1js.OctetString): asn1js.OctetString {
  if (Buffer.isBuffer(value)) {
    return new asn1js.OctetString({
      valueHex: value
    });
  }
  return value;
}

export class IVParameter implements asn1js.LocalValueBlock {
  blockLength: number = 0;
  error: string = '';
  valueBeforeDecode!: ArrayBuffer;
  warnings: string[] = [];

  public iv: Buffer;

  constructor(params: {
    iv: Buffer
  } | {
    schema: asn1js.LocalBaseBlock
  }) {
    if ('schema' in params) {
      this.iv = toBuffer(params.schema as asn1js.OctetString);
    } else {
      this.iv = params.iv;
    }
  }

  fromBER(inputBuffer: ArrayBuffer, inputOffset: number, inputLength: number): number {
    const seq = this.schema();
    seq.fromBER(inputBuffer, inputOffset, inputLength);
    this.iv = toBuffer(seq);
    return 0;
  }

  schema(): asn1js.OctetString {
    return new asn1js.OctetString();
  }

  toSchema(): asn1js.OctetString {
    return new asn1js.OctetString({
      valueHex: bufferToArrayBuffer(this.iv)
    });
  }

  toBER(sizeOnly?: boolean): ArrayBuffer {
    return this.toSchema().toBER(sizeOnly);
  }

  toJSON(): any {
    return this.toSchema().toJSON();
  }
}

export class GCMParameters implements asn1js.LocalValueBlock {
  blockLength: number = 0;
  error: string = '';
  valueBeforeDecode!: ArrayBuffer;
  warnings: string[] = [];

  public nonce: Buffer;
  public icvLen: number;

  constructor(params: {
    nonce: Buffer,
    icvLen: number
  } | {
    schema: asn1js.Sequence
  }) {
    if ('schema' in params) {
      const seq = params.schema;
      this.nonce = toBuffer(seq.valueBlock.value[0] as asn1js.OctetString);
      if (seq.valueBlock.value.length > 1) {
        this.icvLen = toNumber(seq.valueBlock.value[1] as asn1js.Integer);
      } else {
        this.icvLen = 12;
      }
    } else {
      this.nonce = params.nonce;
      this.icvLen = params.icvLen;
    }
  }

  fromBER(inputBuffer: ArrayBuffer, inputOffset: number, inputLength: number): number {
    const seq = this.schema();
    seq.fromBER(inputBuffer, inputOffset, inputLength);
    this.nonce = toBuffer(seq.valueBlock.value[0] as asn1js.OctetString);
    this.icvLen = toNumber(seq.valueBlock.value[0] as asn1js.Integer);
    return 0;
  }

  schema(): asn1js.Sequence {
    return new asn1js.Sequence({
      primitiveSchema: [
        new asn1js.OctetString({
          name: 'aes-nonce'
        }),
        new asn1js.Integer({
          value: 'aes-ICVlen'
        } as any)
      ]
    });
  }

  toSchema(): asn1js.Sequence {
    return new asn1js.Sequence({
      value: [
        new asn1js.OctetString({
          valueHex: this.nonce
        }),
        new asn1js.Integer({
          value: this.icvLen
        })
      ]
    } as any);
  }


  toBER(sizeOnly?: boolean): ArrayBuffer {
    return this.toSchema().toBER(sizeOnly);
  }

  toJSON(): any {
    return this.toSchema().toJSON();
  }
}

export class Asn1AsymAlgorithmType extends asn1js.Integer {
  constructor(params?: asn1js.IntegerParams) {
    super(params);
  }

  public get value(): number {
    const self = this as asn1js.Integer;
    return self.valueBlock.valueDec;
  }

  public set value(v: number) {
    const self = this as asn1js.Integer;
    self.valueBlock.valueDec = v;
  }

  public equals(type: cc.AsymmetricAlgorithmType | number): boolean {
    const self = this as asn1js.Integer;
    return type === self.valueBlock.valueDec;
  }

  public static getObject(value: number);
  public static getObject(value: asn1js.LocalValueBlock);
  public static getObject(value: number | asn1js.LocalValueBlock) {
    if (typeof value === 'number') {
      return new Asn1AsymAlgorithmType({
        value: value
      });
    } else {
      return new Asn1AsymAlgorithmType({
        value: (value as asn1js.Integer).valueBlock.valueDec
      });
    }
  }
}

export class Asn1ChunkFlags extends asn1js.Integer {
  private constructor(value: number) {
    super({
      value: value
    });
  }

  public get value (): number {
    return (this as asn1js.Integer).valueBlock.valueDec;
  }

  public static create(value?: number): Asn1ChunkFlags {
    return new Asn1ChunkFlags(value ? value : 0);
  }

  public static fromValue(value: asn1js.Integer): Asn1ChunkFlags;
  public static fromValue(value: number): Asn1ChunkFlags;
  public static fromValue(value: number | asn1js.Integer): Asn1ChunkFlags {
    if (typeof value === 'number') {
      return new Asn1ChunkFlags(value);
    } else {
      return new Asn1ChunkFlags(value.valueBlock.valueDec);
    }
  }

  get encryptWithAuthKey (): boolean {
    const self = this as asn1js.Integer;
    return !!(self.valueBlock.valueDec & 0x0001);
  }

  set encryptWithAuthKey (v: boolean) {
    const self = this as asn1js.Integer;
    if (v) {
      self.valueBlock.valueDec |= 0x0001;
    } else {
      self.valueBlock.valueDec &= ~0x0001;
    }
  }
}

interface DecoratedChunkAppends<T> {
  decode(id: number, flags: number, dataSeq: asn1js.Sequence): T;
  SCHEMA: any;
}

type DecoratedChunk<T> = T & DecoratedChunkAppends<T>;

function Chunk<T>(constructor: T) {
  (constructor as any).decode = function (seq: asn1js.Sequence, id?: number, flags?: number): T {
    if (typeof id !== 'undefined') {
      return (constructor as any).decodeChunkData(
        id, flags, seq as asn1js.LocalValueBlock
      );
    } else {
      return (constructor as any).decodeChunkData(
        toNumber(seq.valueBlock.value[0] as asn1js.Integer),
        toNumber(seq.valueBlock.value[1] as asn1js.Integer),
        seq.valueBlock.value[2] as asn1js.LocalValueBlock
      );
    }
  };
  (constructor as any).SCHEMA = makeChunkSchema(constructor);
  return constructor as DecoratedChunk<T>;
}

export abstract class Asn1ObjectChunk extends Asn1BaseChunk {
  public readonly id: number;
  public readonly flags: Asn1ChunkFlags;

  protected constructor(id: number, flags?: number) {
    super();
    this.id = id;
    this.flags = flags ? Asn1ChunkFlags.fromValue(flags) : Asn1ChunkFlags.fromValue(0);
  }

  public abstract getChunkData (): asn1js.LocalValueBlock;

  makeChunkPayload(): asn1js.LocalValueBlock {
    const seq = new asn1js.Sequence();
    seq.valueBlock.value.push(new asn1js.Integer({
      value: this.id
    }));
    seq.valueBlock.value.push(this.flags);
    seq.valueBlock.value.push(this.getChunkData());
    return seq;
  }

  toJSON(): asn1js.JsonLocalBaseBlock {
    return this.makeChunkPayload().toJSON();
  }

  toBER(sizeOnly?: boolean): ArrayBuffer {
    return this.makeChunkPayload().toBER(sizeOnly);
  }

  // public static decodeChunkData(id: number, flags: number, seq: asn1js.Sequence): CHUNK_TYPE {
  //   ...
  // }
  // public static create(...): CHUNK_TYPE {
  //   ...
  // }
}

export abstract class Asn1AbstractChunk<TDATA /* extends IAsn1LocalValueable */> extends Asn1ObjectChunk {
  public readonly data: TDATA;

  protected constructor(id: number, flags: number, data: TDATA) {
    super(id, flags);
    this.data = data;
  }

  public getChunkData(): asn1js.LocalValueBlock {
    if ('toBER' in this.data) {
      return this.data as any;
    }
    return (this.data as any).toSchema();
  }
}

const S_Asn1EncryptedChunk: symbol = Symbol('Asn1EncryptedChunkObject');
@Chunk
export class Asn1EncryptedChunk extends Asn1ObjectChunk {
  private _data: asn1js.OctetString;
  public static DATA_SCHEMA = new asn1js.OctetString();
  private _chunkClass: any | undefined;

  constructor(id: number, flags: number, data: asn1js.OctetString, chunkClass: any | undefined) {
    super(id, flags);
    this._data = data;
    this._chunkClass = chunkClass;
    registerSymbol(this, S_Asn1EncryptedChunk);
  }

  public getChunkData(): asn1js.OctetString {
    return this._data;
  }

  public get data(): Buffer {
    return toBuffer(this._data);
  }

  public static isInstance(o: any): boolean {
    return checkSymbol(o, S_Asn1EncryptedChunk);
  }

  public static decodeChunkData(id: number, flags: number, seq: asn1js.LocalValueBlock, chunkClass?: any): Asn1EncryptedChunk {
    return Asn1EncryptedChunk.create(
      id, flags, toBuffer(seq as asn1js.OctetString), chunkClass
    );
  }

  public static create(id: number, flags: number, buffer: Buffer, chunkClass?: any): Asn1EncryptedChunk {
    return new Asn1EncryptedChunk(
      id,
      flags,
      new asn1js.OctetString({
        valueHex: buffer
      }),
      chunkClass
    );
  }

  public static createWithReader(seq: asn1js.Sequence, chunkClass: any): Asn1EncryptedChunk {
    return Asn1EncryptedChunk.decodeChunkData(
      toNumber(seq.valueBlock.value[0] as asn1js.Integer),
      toNumber(seq.valueBlock.value[1] as asn1js.Integer),
      seq.valueBlock.value[2],
      chunkClass
    );
  }

  public getDecryptedChunk(buffer: Buffer): Asn1ObjectChunk {
    const asn = asn1js.fromBER(bufferToArrayBuffer(buffer));
    return this._chunkClass.decode(asn.result, this.id, this.flags);
  }
}

@Chunk
export class Asn1DefaultHeaderImpl extends Asn1ObjectChunk {
  public static CHUNK_ID = ChunkIds.DefaultHeader;
  public static DATA_SCHEMA = new asn1js.Sequence({
    name: 'Jasf4DefaultHeader',
    primitiveSchema: [
      new asn1js.Integer({
        name: 'subVersion'
      }),
      new Asn1AsymAlgorithmType({
        name: 'asymAlgorithmType'
      }),
      new asn1js.ObjectIdentifier({
        name: 'dataCryptoAlgorithm'
      }),
      new asn1js.ObjectIdentifier({
        name: 'dataMacAlgorithm'
      }),
      new asn1js.ObjectIdentifier({
        name: 'fingerprintAlgorithm'
      }),
      new asn1js.OctetString({
        name: 'authKeyCryptionIv'
      })
    ]
  });

  public readonly minorVersion: number;
  public readonly asymAlgorithmType: Asn1AsymAlgorithmType;
  public readonly chunkCryptoAlgorithm: asn1js.ObjectIdentifier;
  public readonly dataCryptoAlgorithm: asn1js.ObjectIdentifier;
  public readonly fingerprintAlgorithm: asn1js.ObjectIdentifier;
  public readonly authKeyCryptionIv: asn1js.OctetString;

  private constructor(minorVersion: number, asymAlgorithmType: Asn1AsymAlgorithmType, chunkCryptoAlgorithm: asn1js.ObjectIdentifier, dataCryptoAlgorithm: asn1js.ObjectIdentifier, fingerprintAlgorithm: asn1js.ObjectIdentifier, authKeyCryptionIv: asn1js.OctetString) {
    super(Asn1DefaultHeaderImpl.CHUNK_ID);
    this.minorVersion = minorVersion;
    this.asymAlgorithmType = asymAlgorithmType;
    this.chunkCryptoAlgorithm = chunkCryptoAlgorithm;
    this.dataCryptoAlgorithm = dataCryptoAlgorithm;
    this.fingerprintAlgorithm = fingerprintAlgorithm;
    this.authKeyCryptionIv = authKeyCryptionIv;
  }

  public getChunkData(): asn1js.Sequence {
    const seq = new asn1js.Sequence();
    seq.valueBlock.value.push(new asn1js.Integer({
      value: this.minorVersion
    }));
    seq.valueBlock.value.push(this.asymAlgorithmType);
    seq.valueBlock.value.push(this.chunkCryptoAlgorithm);
    seq.valueBlock.value.push(this.dataCryptoAlgorithm);
    seq.valueBlock.value.push(this.fingerprintAlgorithm);
    seq.valueBlock.value.push(this.authKeyCryptionIv);
    return seq;
  }

  public static decodeChunkData(id: number, flags: number, seq: asn1js.Sequence): Asn1DefaultHeaderImpl {
    return new Asn1DefaultHeaderImpl(
      toNumber(Asn1AsymAlgorithmType.getObject(seq.valueBlock.value[0])),
      Asn1AsymAlgorithmType.getObject(seq.valueBlock.value[1]),
      copyToAsn1ObjectIdentifier(seq.valueBlock.value[2]),
      copyToAsn1ObjectIdentifier(seq.valueBlock.value[3]),
      copyToAsn1ObjectIdentifier(seq.valueBlock.value[4]),
      copyToAsn1OctetString(seq.valueBlock.value[5])
    );
  }

  public static create (
    minorVersion: asn1js.Integer | number,
    asymAlgorithmType: Asn1AsymAlgorithmType | cc.AsymmetricAlgorithmType,
    chunkCryptoAlgorithm: asn1js.ObjectIdentifier,
    dataCryptoAlgorithm: asn1js.ObjectIdentifier,
    fingerprintAlgorithm: asn1js.ObjectIdentifier,
    authKeyCryptionIv: asn1js.OctetString | Buffer
  ): Asn1DefaultHeaderChunk {
    return new Asn1DefaultHeaderImpl(
      (typeof minorVersion === 'number') ? minorVersion : minorVersion.valueBlock.valueDec,
      (typeof asymAlgorithmType === 'number') ? new Asn1AsymAlgorithmType({
        value: asymAlgorithmType
      }) : asymAlgorithmType,
      chunkCryptoAlgorithm,
      dataCryptoAlgorithm,
      fingerprintAlgorithm,
      Buffer.isBuffer(authKeyCryptionIv) ? new asn1js.OctetString({ valueHex: authKeyCryptionIv }) : authKeyCryptionIv as asn1js.OctetString
    ) as Asn1DefaultHeaderChunk;
  }
}
export const Asn1DefaultHeaderChunk: DecoratedChunk<typeof Asn1DefaultHeaderImpl> = Asn1DefaultHeaderImpl as any;
export type Asn1DefaultHeaderChunk = DecoratedChunk<Asn1DefaultHeaderImpl>;
addChunkType(Asn1DefaultHeaderChunk);

@Chunk
export class Asn1AuthKeyCheckImpl extends Asn1ObjectChunk {
  public static CHUNK_ID = ChunkIds.AuthKeyCheckData;
  public static DATA_SCHEMA = new asn1js.Sequence({
    name: 'Jasf4AuthKeyCheckData',
    primitiveSchema: [
      new asn1js.Any({
        name: 'params'
      }),
      new asn1js.OctetString({
        name: 'key'
      })
    ]
  });

  public readonly params: asn1js.LocalValueBlock;
  public readonly key: asn1js.OctetString;

  private constructor(params: asn1js.LocalValueBlock, key: asn1js.OctetString) {
    super(Asn1AuthKeyCheckImpl.CHUNK_ID);
    this.params = params;
    this.key = key;
  }

  public getChunkData(): asn1js.Sequence {
    const seq = new asn1js.Sequence();
    seq.valueBlock.value.push(this.params);
    seq.valueBlock.value.push(this.key);
    return seq;
  }

  public static decodeChunkData(id: number, flags: number, seq: asn1js.Sequence): Asn1AuthKeyCheckImpl {
    return new Asn1AuthKeyCheckImpl(
      seq.valueBlock.value[0],
      seq.valueBlock.value[1] as asn1js.OctetString
    );
  }

  public static create(params: asn1js.LocalValueBlock, key: asn1js.OctetString | Buffer): Asn1AuthKeyCheckChunk {
    return new Asn1AuthKeyCheckImpl(
      params, Buffer.isBuffer(key) ? new asn1js.OctetString({ valueHex: key }) : key
    ) as Asn1AuthKeyCheckChunk;
  }
}
export const Asn1AuthKeyCheckChunk: DecoratedChunk<typeof Asn1AuthKeyCheckImpl> =  Asn1AuthKeyCheckImpl as any;
export type Asn1AuthKeyCheckChunk = DecoratedChunk<Asn1AuthKeyCheckImpl>;
addChunkType(Asn1AuthKeyCheckChunk);

@Chunk
export class Asn1AsymAlgorithmIdentifierImpl extends Asn1AbstractChunk<AlgorithmIdentifier> {
  public static CHUNK_ID = ChunkIds.AsymAlgorithmIdentifier;
  public static DATA_SCHEMA = new AlgorithmIdentifier();

  private constructor(flags: number, data: AlgorithmIdentifier) {
    super(Asn1AsymAlgorithmIdentifierImpl.CHUNK_ID, flags, data);
  }

  public static decodeChunkData(id: number, flags: number, seq: asn1js.LocalValueBlock): Asn1AsymAlgorithmIdentifierImpl {
    return new Asn1AsymAlgorithmIdentifierImpl(
      flags, new AlgorithmIdentifier({
        schema: seq
      })
    );
  }

  public static create(data: AlgorithmIdentifier): Asn1AsymAlgorithmIdentifierChunk {
    return new Asn1AsymAlgorithmIdentifierImpl(0, data) as Asn1AsymAlgorithmIdentifierChunk;
  }
}
export const Asn1AsymAlgorithmIdentifierChunk: DecoratedChunk<typeof Asn1AsymAlgorithmIdentifierImpl> =  Asn1AsymAlgorithmIdentifierImpl as any;
export type Asn1AsymAlgorithmIdentifierChunk = DecoratedChunk<Asn1AsymAlgorithmIdentifierImpl>;
addChunkType(Asn1AsymAlgorithmIdentifierChunk);

@Chunk
export class Asn1DataCryptoAlgorithmSpecImpl extends Asn1AbstractChunk<asn1js.LocalValueBlock> {
  public static CHUNK_ID = ChunkIds.DataCryptoAlgorithmParameterSpec;
  public static DATA_SCHEMA = new AlgorithmIdentifier();

  private constructor(flags: number, data: asn1js.LocalValueBlock) {
    super(Asn1DataCryptoAlgorithmSpecImpl.CHUNK_ID, flags, data);
  }

  public static decodeChunkData(id: number, flags: number, data: asn1js.LocalValueBlock): Asn1DataCryptoAlgorithmSpecImpl {
    return new Asn1DataCryptoAlgorithmSpecImpl(
      flags, data
    );
  }

  public static create<T extends asn1js.LocalValueBlock>(data: T): Asn1DataCryptoAlgorithmSpecChunk {
    return new Asn1DataCryptoAlgorithmSpecImpl(0, data) as Asn1DataCryptoAlgorithmSpecChunk;
  }

  public convertTo(type: any) {
    return new type({
      schema: this.data
    });
  }
}
export const Asn1DataCryptoAlgorithmSpecChunk: DecoratedChunk<typeof Asn1DataCryptoAlgorithmSpecImpl> = Asn1DataCryptoAlgorithmSpecImpl as any;
export type Asn1DataCryptoAlgorithmSpecChunk = DecoratedChunk<Asn1DataCryptoAlgorithmSpecImpl>;
addChunkType(Asn1DataCryptoAlgorithmSpecChunk);

@Chunk
export class Asn1DataMacAlgorithmSpecImpl extends Asn1AbstractChunk<AlgorithmIdentifier> {
  public static CHUNK_ID = ChunkIds.DataMacAlgorithm;
  public static DATA_SCHEMA = new AlgorithmIdentifier();

  private constructor(flags: number, data: AlgorithmIdentifier) {
    super(Asn1DataMacAlgorithmSpecImpl.CHUNK_ID, flags, data);
  }

  public static decodeChunkData(id: number, flags: number, seq: asn1js.LocalValueBlock): Asn1DataMacAlgorithmSpecImpl {
    return new Asn1DataMacAlgorithmSpecImpl(
      flags, new AlgorithmIdentifier({
        schema: seq
      })
    );
  }

  public static create(data: AlgorithmIdentifier): Asn1DataMacAlgorithmSpecChunk {
    return new Asn1DataMacAlgorithmSpecImpl(0, data) as Asn1DataMacAlgorithmSpecChunk;
  }
}
export const Asn1DataMacAlgorithmSpecChunk: DecoratedChunk<typeof Asn1DataMacAlgorithmSpecImpl> =  Asn1DataMacAlgorithmSpecImpl as any;
export type Asn1DataMacAlgorithmSpecChunk = DecoratedChunk<Asn1DataMacAlgorithmSpecImpl>;
addChunkType(Asn1DataMacAlgorithmSpecChunk);

@Chunk
export class Asn1EphemeralECPublicKeyImpl extends Asn1AbstractChunk<PublicKeyInfo> {
  public static CHUNK_ID = ChunkIds.EphemeralECPublicKey;
  public static DATA_SCHEMA = new PublicKeyInfo();

  private constructor(flags: number, data: PublicKeyInfo) {
    super(Asn1EphemeralECPublicKeyImpl.CHUNK_ID, flags, data);
  }

  public static decodeChunkData(id: number, flags: number, seq: asn1js.LocalValueBlock): Asn1EphemeralECPublicKeyImpl {
    return new Asn1EphemeralECPublicKeyImpl(
      flags, new PublicKeyInfo({
        schema: seq
      })
    );
  }

  public static create(data: PublicKeyInfo | Buffer): Asn1EphemeralECPublicKeyChunk {
    const publicKeyInfo = Buffer.isBuffer(data) ?
      asn1js.fromBER(bufferToArrayBuffer(data)).result : data;
    return new Asn1EphemeralECPublicKeyImpl(0, publicKeyInfo) as Asn1EphemeralECPublicKeyChunk;
  }
}
export const Asn1EphemeralECPublicKeyChunk: DecoratedChunk<typeof Asn1EphemeralECPublicKeyImpl> =  Asn1EphemeralECPublicKeyImpl as any;
export type Asn1EphemeralECPublicKeyChunk = DecoratedChunk<Asn1EphemeralECPublicKeyImpl>;
addChunkType(Asn1EphemeralECPublicKeyChunk);

const DATA_KEY_INFO_SIGNATURE = Buffer.from([0x01, 0xcf, 0xcb, 0xff]);
@Chunk
export class Asn1DataKeyInfoImpl extends Asn1ObjectChunk {
  public static CHUNK_ID = ChunkIds.DataKeyInfo;
  public static SIGNATURE = DATA_KEY_INFO_SIGNATURE;
  public static DATA_SCHEMA = new asn1js.Sequence({
    name: 'Jasf4DataKeyInfo',
    primitiveSchema: [
      new asn1js.OctetString({
        name: 'signature'
      }),
      new asn1js.OctetString({
        name: 'dataKey'
      }),
      new asn1js.OctetString({
        name: 'macKey'
      })
    ]
  });

  public readonly signature: asn1js.OctetString;
  public readonly dataKey: asn1js.OctetString;
  public readonly macKey: asn1js.OctetString;

  private constructor(signature: asn1js.OctetString, dataKey: asn1js.OctetString, macKey: asn1js.OctetString, flags?: number) {
    super(Asn1DataKeyInfoImpl.CHUNK_ID, flags);
    if (typeof flags !== 'undefined') {
      this.flags.encryptWithAuthKey = true;
    }
    this.signature = signature;
    this.dataKey = dataKey;
    this.macKey = macKey;
  }

  public getChunkData(): asn1js.Sequence {
    const seq = new asn1js.Sequence();
    seq.valueBlock.value.push(this.signature);
    seq.valueBlock.value.push(this.dataKey);
    seq.valueBlock.value.push(this.macKey);
    return seq;
  }

  public static create(dataKey: Buffer, macKey: Buffer, flags?: Asn1ChunkFlags): Asn1DataKeyInfoChunk {
    return new Asn1DataKeyInfoImpl(
      new asn1js.OctetString({
        valueHex: DATA_KEY_INFO_SIGNATURE.slice(0, DATA_KEY_INFO_SIGNATURE.byteLength)
      }),
      new asn1js.OctetString({
        valueHex: dataKey
      }),
      new asn1js.OctetString({
        valueHex: macKey
      }),
      flags ? flags.value : 0
    ) as Asn1DataKeyInfoChunk;
  }

  public static decodeChunkData(id: number, flags: number, input: asn1js.Sequence | Buffer): Asn1DataKeyInfoImpl {
    const seq: asn1js.Sequence = Buffer.isBuffer(input) ?
      asn1js.fromBER(bufferToArrayBuffer(input)).result as asn1js.Sequence : input;
    return new Asn1DataKeyInfoImpl(
      copyToAsn1OctetString(seq.valueBlock.value[0]),
      copyToAsn1OctetString(seq.valueBlock.value[1]),
      copyToAsn1OctetString(seq.valueBlock.value[2]),
      flags
    );
  }

  public validate(): boolean {
    return DATA_KEY_INFO_SIGNATURE.equals(arrayBufferToBuffer(this.signature.valueBlock.valueHex));
  }
}
export const Asn1DataKeyInfoChunk: DecoratedChunk<typeof Asn1DataKeyInfoImpl> =  Asn1DataKeyInfoImpl as any;
export type Asn1DataKeyInfoChunk = DecoratedChunk<Asn1DataKeyInfoImpl>;
addChunkType(Asn1DataKeyInfoChunk);

@Chunk
export class Asn1EncryptedDataKeyInfoImpl extends Asn1AbstractChunk<asn1js.OctetString> {
  public static CHUNK_ID = ChunkIds.EncryptedDataKeyInfo;
  public static DATA_SCHEMA = new asn1js.OctetString();

  private constructor(flags: number, data: asn1js.OctetString) {
    super(Asn1EncryptedDataKeyInfoImpl.CHUNK_ID, flags, data);
  }

  public static decodeChunkData(id: number, flags: number, data: asn1js.LocalValueBlock): Asn1EncryptedDataKeyInfoImpl {
    return new Asn1EncryptedDataKeyInfoImpl(
      flags, data as asn1js.OctetString
    );
  }

  public static create(data: asn1js.OctetString | Buffer): Asn1EncryptedDataKeyInfoChunk {
    return new Asn1EncryptedDataKeyInfoImpl(
      0,
      Buffer.isBuffer(data) ? new asn1js.OctetString({ valueHex: data }) : data
    ) as Asn1EncryptedDataKeyInfoChunk;
  }

  public getData(): Buffer {
    return arrayBufferToBuffer(this.data.valueBlock.valueHex);
  }
}
export const Asn1EncryptedDataKeyInfoChunk: DecoratedChunk<typeof Asn1EncryptedDataKeyInfoImpl> =  Asn1EncryptedDataKeyInfoImpl as any;
export type Asn1EncryptedDataKeyInfoChunk = DecoratedChunk<Asn1EncryptedDataKeyInfoImpl>;
addChunkType(Asn1EncryptedDataKeyInfoChunk);

@Chunk
export class Asn1DHCheckDataImpl extends Asn1AbstractChunk<asn1js.OctetString> {
  public static CHUNK_ID = ChunkIds.DHCheckData;
  public static DATA_SCHEMA = new asn1js.OctetString();

  private constructor(flags: number, data: asn1js.OctetString) {
    super(Asn1DHCheckDataImpl.CHUNK_ID, flags, data);
  }

  public static decodeChunkData(id: number, flags: number, data: asn1js.LocalValueBlock): Asn1DHCheckDataImpl {
    return new Asn1DHCheckDataImpl(
      flags, data as asn1js.OctetString
    );
  }

  public static create(data: asn1js.OctetString | Buffer): Asn1DHCheckDataChunk {
    const flags = Asn1ChunkFlags.create();
    flags.encryptWithAuthKey = true;
    return new Asn1DHCheckDataImpl(
      flags.value,
      Buffer.isBuffer(data) ? new asn1js.OctetString({ valueHex: data }) : data
    ) as Asn1DHCheckDataChunk;
  }

  public equals(data: Buffer): boolean {
    return arrayBufferToBuffer(this.data.valueBlock.valueHex).equals(data);
  }
}
export const Asn1DHCheckDataChunk: DecoratedChunk<typeof Asn1DHCheckDataImpl> =  Asn1DHCheckDataImpl as any;
export type Asn1DHCheckDataChunk = DecoratedChunk<Asn1DHCheckDataImpl>;
addChunkType(Asn1DHCheckDataChunk);

@Chunk
export class Asn1DataImpl extends Asn1AbstractChunk<asn1js.OctetString> {
  public static CHUNK_ID = ChunkIds.Data;
  public static DATA_SCHEMA = new asn1js.OctetString();

  private constructor(flags: number, data: asn1js.OctetString) {
    super(Asn1DataImpl.CHUNK_ID, flags, data);
  }

  public static decodeChunkData(id: number, flags: number, data: asn1js.LocalValueBlock): Asn1DataImpl {
    return new Asn1DataImpl(
      flags, data as asn1js.OctetString
    );
  }

  public static create(data: asn1js.OctetString | Buffer): Asn1DataChunk {
    return new Asn1DataImpl(
      0,
      Buffer.isBuffer(data) ? new asn1js.OctetString({ valueHex: data }) : data
    ) as Asn1DataChunk;
  }

  public getData(): Buffer {
    return arrayBufferToBuffer(this.data.valueBlock.valueHex);
  }
}
export const Asn1DataChunk: DecoratedChunk<typeof Asn1DataImpl> =  Asn1DataImpl as any;
export type Asn1DataChunk = DecoratedChunk<Asn1DataImpl>;
addChunkType(Asn1DataChunk);

@Chunk
export class Asn1MacOfEncryptedDataImpl extends Asn1AbstractChunk<asn1js.OctetString> {
  public static CHUNK_ID = ChunkIds.MacOfEncryptedData;
  public static DATA_SCHEMA = new asn1js.OctetString();

  private constructor(flags: number, data: asn1js.OctetString) {
    super(Asn1MacOfEncryptedDataImpl.CHUNK_ID, flags, data);
  }

  public static decodeChunkData(id: number, flags: number, data: asn1js.LocalValueBlock): Asn1MacOfEncryptedDataImpl {
    return new Asn1MacOfEncryptedDataImpl(
      flags, data as asn1js.OctetString
    );
  }

  public static create(data: asn1js.OctetString | Buffer): Asn1MacOfEncryptedDataChunk {
    return new Asn1MacOfEncryptedDataImpl(
      0,
      Buffer.isBuffer(data) ? new asn1js.OctetString({ valueHex: data }) : data
    ) as Asn1MacOfEncryptedDataChunk;
  }

  public getData(): Buffer {
    return arrayBufferToBuffer(this.data.valueBlock.valueHex);
  }
}
export const Asn1MacOfEncryptedDataChunk: DecoratedChunk<typeof Asn1MacOfEncryptedDataImpl> =  Asn1MacOfEncryptedDataImpl as any;
export type Asn1MacOfEncryptedDataChunk = DecoratedChunk<Asn1MacOfEncryptedDataImpl>;
addChunkType(Asn1MacOfEncryptedDataChunk);

@Chunk
export class Asn1FingerprintImpl extends Asn1AbstractChunk<asn1js.OctetString> {
  public static CHUNK_ID = ChunkIds.Fingerprint;
  public static DATA_SCHEMA = new asn1js.OctetString();

  private constructor(flags: number, data: asn1js.OctetString) {
    super(Asn1FingerprintImpl.CHUNK_ID, flags, data);
  }

  public static decodeChunkData(id: number, flags: number, data: asn1js.LocalValueBlock): Asn1FingerprintImpl {
    return new Asn1FingerprintImpl(
      flags, data as asn1js.OctetString
    );
  }

  public static create(data: asn1js.OctetString | Buffer): Asn1FingerprintChunk {
    return new Asn1FingerprintImpl(
      0,
      Buffer.isBuffer(data) ? new asn1js.OctetString({ valueHex: data }) : data
    ) as Asn1FingerprintChunk;
  }

  public getData(): Buffer {
    return arrayBufferToBuffer(this.data.valueBlock.valueHex);
  }
}
export const Asn1FingerprintChunk: DecoratedChunk<typeof Asn1FingerprintImpl> =  Asn1FingerprintImpl as any;
export type Asn1FingerprintChunk = DecoratedChunk<Asn1FingerprintImpl>;
addChunkType(Asn1FingerprintChunk);

@Chunk
export class Asn1SignedFingerprintImpl extends Asn1AbstractChunk<asn1js.OctetString> {
  public static CHUNK_ID = ChunkIds.SignedFingerprint;
  public static DATA_SCHEMA = new asn1js.OctetString();

  private constructor(flags: number, data: asn1js.OctetString) {
    super(Asn1SignedFingerprintImpl.CHUNK_ID, flags, data);
  }

  public static decodeChunkData(id: number, flags: number, data: asn1js.LocalValueBlock): Asn1SignedFingerprintImpl {
    return new Asn1SignedFingerprintImpl(
      flags, data as asn1js.OctetString
    );
  }

  public static create(data: asn1js.OctetString | Buffer): Asn1SignedFingerprintChunk {
    return new Asn1SignedFingerprintImpl(
      0,
      Buffer.isBuffer(data) ? new asn1js.OctetString({ valueHex: data }) : data
    ) as Asn1SignedFingerprintChunk;
  }

  public getData(): Buffer {
    return arrayBufferToBuffer(this.data.valueBlock.valueHex);
  }
}
export const Asn1SignedFingerprintChunk: DecoratedChunk<typeof Asn1SignedFingerprintImpl> =  Asn1SignedFingerprintImpl as any;
export type Asn1SignedFingerprintChunk = DecoratedChunk<Asn1SignedFingerprintImpl>;
addChunkType(Asn1SignedFingerprintChunk);

@Chunk
export class Asn1TimestampImpl extends Asn1AbstractChunk<asn1js.Any> {
  public static CHUNK_ID = ChunkIds.Timestamp;
  public static DATA_SCHEMA = new asn1js.Any();

  private constructor(flags: number, data: asn1js.Any) {
    super(Asn1TimestampImpl.CHUNK_ID, flags, data);
  }

  public static decodeChunkData(id: number, flags: number, data: asn1js.LocalValueBlock): Asn1TimestampImpl {
    return new Asn1TimestampImpl(
      flags, data as any
    );
  }

  public static create(data: asn1js.Any): Asn1TimestampChunk {
    return new Asn1TimestampImpl(
      0,
      data
    ) as Asn1TimestampChunk;
  }
}
export const Asn1TimestampChunk: DecoratedChunk<typeof Asn1TimestampImpl> =  Asn1TimestampImpl as any;
export type Asn1TimestampChunk = DecoratedChunk<Asn1TimestampImpl>;
addChunkType(Asn1TimestampChunk);

@Chunk
export class Asn1CustomDataImpl extends Asn1AbstractChunk<asn1js.OctetString> {
  public static CHUNK_ID = ChunkIds.CustomBegin;
  public static DATA_SCHEMA = new asn1js.OctetString();

  private constructor(customChunkId: number, flags: number, data: asn1js.OctetString) {
    super(ChunkIds.CustomBegin + customChunkId, flags, data);
  }

  public static decodeChunkData(id: number, flags: number, data: asn1js.LocalValueBlock): Asn1CustomDataImpl {
    return new Asn1CustomDataImpl(
      id - ChunkIds.CustomBegin, flags, data as asn1js.OctetString
    );
  }

  public static create(customChunkId: number, flags: number | Asn1ChunkFlags, data: asn1js.OctetString | Buffer): Asn1CustomDataChunk {
    return new Asn1CustomDataImpl(
      customChunkId,
      (typeof flags === 'number') ? flags : flags.value,
      Buffer.isBuffer(data) ? new asn1js.OctetString({ valueHex: data }) : data
    ) as Asn1CustomDataChunk;
  }
}
export const Asn1CustomDataChunk: DecoratedChunk<typeof Asn1CustomDataImpl> = Asn1CustomDataImpl as any;
export type Asn1CustomDataChunk = DecoratedChunk<Asn1CustomDataImpl>;
addChunkType(Asn1CustomDataChunk);
