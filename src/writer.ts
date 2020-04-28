import streams from 'stream';
import {
  CustomChunk, IWriterParams, NotSupportedVersionError
} from './common';
import {
  IExactWriterParams
} from './internal/intl';
import {
  IWriterHandlers,
  WriterDelegate
} from './internal/writer-delegate';
import {
  Jasf4WriterDelegate
} from './internal/jasf4/writer-delegate';
import versionRouter from './version_router';

export class Writer extends streams.Transform {
  private _delegate: WriterDelegate;

  constructor(props: IWriterParams) {
    super();
    const self = this;
    const exactProps: IExactWriterParams = {
      operationType: props.operationType,
      version: props.version || versionRouter.getLatestWriterVersion(),
      excludeHeader: props.excludeHeader || false,
      authKey: Buffer.isBuffer(props.authKey) ? props.authKey : Buffer.from(props.authKey),
      key: props.key,
      tsaLocation: props.tsaLocation
    };
    const writerHandlers: IWriterHandlers = {
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
      emitError(e: any): void {
        self.emit('error', e);
      }
    };

    if (props.operationType.isSign()) {
      if (!props.key.isPrivate()) {
        throw new Error('need privateKey');
      }
      if (!props.key.signable) {
        throw new Error('wrong key type');
      }
    } else if (props.operationType.isPublicEncrypt()) {
      if (!props.key.isPublic()) {
        throw new Error('need publicKey');
      }
    }

    this._delegate = versionRouter.createWriterDelegate(writerHandlers, exactProps);
  }

  public init(): Promise<void> {
    return this._delegate.init();
  }

  public addCustomChunk(chunk: CustomChunk): Promise<void> {
    return this._delegate.addCustomChunk(chunk);
  }

  _write(chunk: any, encoding: string, callback: (error?: (Error | null)) => void): void {
    let bufferChunk = chunk;
    if (!Buffer.isBuffer(chunk)) {
      bufferChunk = Buffer.from(chunk);
    }
    this._delegate.write(bufferChunk, callback);
  }

  _final(callback: (error?: (Error | null)) => void): void {
    this._delegate.final(callback);
  }
}
