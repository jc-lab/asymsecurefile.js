import {
  CustomChunk
} from '../common';
import ReadBuffer from '../read-buffer';
import {
  ParseResult
} from './intl';
import {
  AsymmetricKeyObject
} from 'commons-crypto';

export interface IReaderInitParams {
  authKey?: Buffer;
  key: AsymmetricKeyObject;
}

export interface ReaderDelegate {
  setAuthKey(authKey: Buffer): void;
  init(params: IReaderInitParams): Promise<void>;
  final(callback: (err: any) => void);
  parse(readBuffer: ReadBuffer): Promise<ParseResult>;
}

export interface IReaderHandlers {
  pushCustomChunk(chunk: CustomChunk): void;
  headerComplete(): void;
  push(chunk: Buffer): Promise<boolean>;
}
