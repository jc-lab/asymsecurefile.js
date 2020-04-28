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

export interface IExactReaderInitParams {
  authKey: Buffer;
  key: AsymmetricKeyObject;
}

export interface ReaderDelegate {
  init(params: IExactReaderInitParams): Promise<void>;
  final(callback: (err: any) => void);
  parse(readBuffer: ReadBuffer): Promise<ParseResult>;
}

export interface IReaderHandlers {
  pushCustomChunk(chunk: CustomChunk): void;
  headerComplete(): void;
  push(chunk: Buffer): Promise<boolean>;
}
