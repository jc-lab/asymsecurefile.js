import * as cc from 'commons-crypto';
import * as streams from 'stream';

export class OperationType {
  private _value: number;

  public static readonly SIGN = new OperationType(1);
  public static readonly PUBLIC_ENCRYPT = new OperationType(2);

  constructor(value: number) {
    this._value = value;
  }

  get value (): number {
    return this._value;
  }

  equals (o: OperationType) {
    return o.value == this.value;
  }

  isSign(): boolean {
    return this.value == OperationType.SIGN.value;
  }

  isPublicEncrypt(): boolean {
    return this.value == OperationType.PUBLIC_ENCRYPT.value;
  }
}

export interface IWriterParams {
  operationType: OperationType;
  authKey: string | Buffer;
  excludeHeader?: boolean;
  version?: number;
  key: cc.AsymmetricKeyObject;
  tsaLocation?: string;
}

export interface IReaderParamsBase extends streams.DuplexOptions {
  authKey?: string | Buffer;
  key?: AsymmetricKeyObject;
}

export interface IReaderParamsWithoutExcludeHeader extends IReaderParamsBase {
  excludeHeader?: false;
}
export interface IReaderParamsWithExcludeHeader extends IReaderParamsBase {
  excludeHeader: true;
  version: number;
}

export type IReaderParams = IReaderParamsWithoutExcludeHeader | IReaderParamsWithExcludeHeader;

export interface ReaderInitParams {
  authKey?: string | Buffer;
  key?: AsymmetricKeyObject;
}

export * from './custom-chunk';

import AsymAlgorithm from './asym_algorithm';

import NotSupportedVersionError from './errors/not-supported-version';
import {
  AsymmetricKeyObject
} from 'commons-crypto';

export {AsymAlgorithm,
  NotSupportedVersionError};

export function authKeyToBuffer(input: string | Buffer): Buffer {
  return Buffer.isBuffer(input) && input || Buffer.from(input, 'utf8');
}
