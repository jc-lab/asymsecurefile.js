/*! *****************************************************************************
Copyright (c) JC-Lab. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License. You may obtain a copy of the
License at http://www.apache.org/licenses/LICENSE-2.0

THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION ANY IMPLIED
WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A PARTICULAR PURPOSE,
MERCHANTABLITY OR NON-INFRINGEMENT.

See the Apache Version 2.0 License for specific language governing permissions
and limitations under the License.
***************************************************************************** */

import * as streams from 'stream';
import WaitSignal from 'wait-signal';
import SignatureHeader from './signature_header';
import ReadBuffer from './read-buffer';
import {
  ParseResult
} from './internal/intl';
import {
  IReaderParams,
  ReaderInitParams
} from './common';
import {
  CustomChunk
} from './custom-chunk';
import {
  IExactReaderInitParams,
  IReaderHandlers,
  ReaderDelegate
} from './internal/reader-delegate';
import versionRouter from './version_router';

const METHOD_PARSE_SIGNATURE = Symbol('PARSE_SIGNATURE');
const METHOD_PARSE_PAYLOAD = Symbol('PARSE_PAYLOAD');

enum ParseStep {
  SIGNATURE,
  PAYLOAD
}

interface WaitingPromise {
  resolve: any;
  reject: any;
}

type ParserMethod = (chunk: ReadBuffer) => Promise<ParseResult>;

const S_readerHandlers = Symbol('readerHandlers');

export declare interface Reader {
  on(event: 'header-complete', listener: (next: () => void) => void): this;
  on(event: 'custom-chunk', listener: (chunk: CustomChunk) => void): this;
  on(event: string, listener: Function): this;

  emit(event: 'header-complete'): boolean;
  emit(event: 'custom-chunk', chunk: CustomChunk): boolean;
  emit(event: string | symbol, ...args: any[]): boolean;
}
export class Reader extends streams.Transform {
  private _destroyed: boolean = false;
  private _partial: boolean = false;

  private _opts?: IReaderParams;

  private _totalReadBytes: number;
  private _parsers: ParserMethod[];
  private _buffer: Buffer | null;
  private _knownSize: number = -1;

  private _signatureHeader = new SignatureHeader();
  private _delegate!: ReaderDelegate;

  private [S_readerHandlers]: IReaderHandlers;

  private _headerReadComplete: boolean = false;
  private _customChunks: Map<number, CustomChunk> = new Map();

  private _initWaitSignal: WaitSignal = new WaitSignal();

  constructor(opts?: IReaderParams) {
    super(opts);
    const self = this;
    this._opts = opts;
    this._destroyed = false;
    this._partial = false;
    this._totalReadBytes = 0;
    this._parsers = [
      this[METHOD_PARSE_SIGNATURE].bind(this),
      this[METHOD_PARSE_PAYLOAD].bind(this)
    ];
    this._buffer = null;

    this[S_readerHandlers] = {
      push: chunk => new Promise<boolean>((resolve, reject) => {
        const trySend = () => {
          if (self.isPaused()) {
            setTimeout(trySend, 1);
          } else {
            resolve(self.push(chunk));
          }
        };
        trySend();
      }),
      pushCustomChunk: (chunk: CustomChunk) => {
        this._customChunks.set(chunk.id, chunk);
        self.emit('custom-chunk', chunk);
      },
      headerComplete: () => {
        self._headerReadComplete = true;
        self.emit('header-complete');
        if (this._opts && this._opts.authKey && this._opts.key) {
          this._runAutoInit({
            authKey: Buffer.isBuffer(this._opts.authKey) ? this._opts.authKey : Buffer.from(this._opts.authKey),
            key: this._opts.key
          });
        }
      }
    };
  }

  public setKnownSize(v: number) {
    this._knownSize = v;
  }

  private async [METHOD_PARSE_SIGNATURE](buffer: ReadBuffer): Promise<ParseResult> {
    if (buffer.remaining < SignatureHeader.SIGNATURE_SIZE) {
      return Promise.resolve(ParseResult.NEED_MORE);
    }

    this._signatureHeader.read(buffer);

    try {
      this._delegate = versionRouter.createReaderDelegate(this[S_readerHandlers], this._signatureHeader.version);
    } catch (e) {
      return Promise.reject(e);
    }

    return Promise.resolve(ParseResult.DONE);
  }

  private async [METHOD_PARSE_PAYLOAD](buffer: ReadBuffer): Promise<ParseResult> {
    return this._delegate.parse(buffer);
  }

  _write(chunk: any, encoding: string, callback: (error?: (Error | null)) => void): void {
    if (this._destroyed) return;
    const runImpl = () => {
      (async () => {
        try {
          const dataBuf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as string, encoding as BufferEncoding);
          let footerBuffer: Buffer | null = null;
          if (this._parsers.length) {
            const remainingPayload = (this._knownSize < 0) ? (-1) : (this._knownSize - this._totalReadBytes);
            let remainingBuf = this._buffer ? Buffer.concat([this._buffer, dataBuf]) : dataBuf;
            let data;
            if ((remainingPayload >= 0) && (remainingBuf.length > remainingPayload)) {
              data = new ReadBuffer({
                buffer: remainingBuf,
                offset: 0,
                limit: remainingPayload,
                afterReadHandler: (v) => {
                  this._totalReadBytes += v;
                }
              });
            } else {
              data = new ReadBuffer({
                buffer: remainingBuf,
                afterReadHandler: (v) => {
                  this._totalReadBytes += v;
                }
              });
            }

            this._buffer = null;

            while (this._parsers.length && data.remaining) {
              let parser = this._parsers[0];
              const res = await parser(data);

              if (res == ParseResult.NEED_MORE) {
                this._buffer = data.readRemainingBuffer();
                break;
              } else if (res == ParseResult.DONE) {
                // NEXT
                this._parsers.shift();
              }
            }
            if (this._parsers.length == 0) {
              this._partial = false;
            }

            if (data.footerSize > 0)
              footerBuffer = data.getFooterBuffer();
          } else {
            footerBuffer = dataBuf;
          }
          callback();
        } catch (err) {
          this.emit('error', err);
        }
      })();
    };
    if (this._headerReadComplete) {
      this._initWaitSignal.wait((value, err) => {
        if (err) {
          callback(err);
          return;
        }
        runImpl();
      });
    } else {
      runImpl();
    }
  }

  _final(callback: (error?: (Error | null)) => void): void {
    if (this._partial)
      return this.destroy(new Error('Unexpected end of data'));
    this._delegate.final((err) => {
      if (err) {
        callback(err);
        return;
      }
      callback();
    });
    this.destroy();
  }

  destroy(err?: Error): void {
    if (this._destroyed) return ;
    this._destroyed = true;

    if (err) this.emit('error', err);
    this.emit('close');
  }

  private _runAutoInit(params: IExactReaderInitParams) {
    this._delegate.init(params)
      .then(() => {
        this._initWaitSignal.signal();
      })
      .catch((err) => {
        this._initWaitSignal.throw(err);
      });
  }

  public init(params: ReaderInitParams): Promise<void> {
    if (!params.authKey) {
      return Promise.reject(new Error('authKey is not defined'));
    }
    const authKey = Buffer.isBuffer(params.authKey) ? params.authKey : params.authKey && Buffer.from(params.authKey);
    const key = params.key || (this._opts && this._opts.key);
    if (!authKey) {
      return Promise.reject(new Error('need authKey'));
    }
    if (!key) {
      return Promise.reject(new Error('need key'));
    }
    return this._delegate.init({
      authKey: authKey,
      key: key
    })
      .then(() => this._initWaitSignal.signal())
      .catch((e) => {
        this._initWaitSignal.throw(e);
        return Promise.reject(e);
      });
  }

  public getCustomChunk(id: number): CustomChunk | undefined {
    if (!this._headerReadComplete) {
      throw new Error('Header read not completed');
    }
    return this._customChunks.get(id);
  }
}

export default Reader;
