import asn1js from 'asn1js';
import * as cc from 'commons-crypto';
import {
  IExactReaderInitParams,
  IReaderHandlers,
  ReaderDelegate
} from '../reader-delegate';
import ReadBuffer from '../../read-buffer';
import {
  ParseResult,
  rfc5869
} from '../intl';
import {
  Asn1Reader,
  Asn1SequenceResult,
  Asn1ParseResult
} from 'asn1-stream';
import {
  CustomChunk,
  CustomChunkFlags,
  OperationType
} from '../../common';
import {
  parseChunk
} from './chunk-resolver';
import {
  Asn1AuthKeyCheckChunk,
  Asn1CustomDataChunk,
  Asn1DataChunk,
  Asn1DataCryptoAlgorithmSpecChunk,
  Asn1DataKeyInfoChunk,
  Asn1DefaultHeaderChunk,
  Asn1DHCheckDataChunk,
  Asn1EncryptedChunk,
  Asn1EncryptedDataKeyInfoChunk,
  Asn1EphemeralECPublicKeyChunk,
  Asn1FingerprintChunk,
  Asn1MacOfEncryptedDataChunk,
  Asn1ObjectChunk,
  Asn1SignedFingerprintChunk,
  ChunkIds
} from './asn-objects';
import {
  checkAuthKey
} from './jasf4-common';
import * as cryptoUtils from '../crypto-utils';
import {
  arrayBufferToBuffer
} from '../asn-utils';
import {
  hkdfCompute
} from '../crypto-utils';
import * as crypto from 'crypto';
import ValidateFailedError from '../../errors/validate-failed';
import {
  AsymmetricKeyObject
} from 'commons-crypto';

const S_asymKey = Symbol('asymKey');
export class Jasf4ReaderDelegate implements ReaderDelegate {
  private _readerHandlers: IReaderHandlers;
  private _asnReader: Asn1Reader;
  private _asnSequence: number;

  private [S_asymKey]!: AsymmetricKeyObject;

  private _minorVersion: number = 0;
  private _operationType!: OperationType;
  private _chunks: Map<number, Asn1ObjectChunk> = new Map();
  private _pendingChunks: Asn1ObjectChunk[] = [];

  private _fingerprintPending: Buffer[] = [];
  private _fingerprintHash: crypto.Hash | null | false = null;
  private _computedFingerprint!: Buffer;

  private _headerReadCompleted: boolean = false;
  private _dataReadReady: boolean = false;
  private _dataCryptoAlgorithm!: cryptoUtils.ICreateCipherResult;
  private _dataDecipher!: crypto.DecipherGCM;
  private _dataMac: crypto.Hmac | null = null;

  private _defaultHeaderChunk!: Asn1DefaultHeaderChunk;
  private _authEncryptKey!: Buffer;
  private _authMacKey!: Buffer;
  private _authKeyCryptoIv!: Buffer;

  constructor(readerHandlers: IReaderHandlers) {
    this._readerHandlers = readerHandlers;
    this._asnSequence = 0;
    this._asnReader = new Asn1Reader({
      stripSequence: true
    });
    this._asnReader
      .on('begin-sequence', (result: Asn1SequenceResult) => {
        this._asnSequence = 0;
        this._updateFingerprintPayload(result.raw);
      })
      .on('data', (result: Asn1ParseResult) => {
        const obj = result.result;
        switch (this._asnSequence) {
        case 0:
          this._updateFingerprintPayload(arrayBufferToBuffer(result.result.valueBeforeDecode));
          this._minorVersion = (obj as asn1js.Integer).valueBlock.valueDec;
          break;
        case 1:
          this._updateFingerprintPayload(arrayBufferToBuffer(result.result.valueBeforeDecode));
          this._operationType = new OperationType((obj as asn1js.Integer).valueBlock.valueDec);
          break;
        default:
          do {
            const chunk = parseChunk(result.result as asn1js.Sequence);
            if (chunk.id != ChunkIds.Fingerprint) {
              this._updateFingerprintPayload(arrayBufferToBuffer(result.result.valueBeforeDecode));
            }
            if (chunk.id === ChunkIds.DefaultHeader) {
              const chunkImpl = chunk as Asn1DefaultHeaderChunk;
              this._fingerprintHash = cryptoUtils.createHash({
                oid: chunkImpl.fingerprintAlgorithm.valueBlock.toString()
              }).createHash();
              let buf;
              while ((buf = this._fingerprintPending.shift())) {
                this._fingerprintHash.update(buf);
              }
            } else if (chunk.id === ChunkIds.Fingerprint) {
              const digest = (this._fingerprintHash as crypto.Hash).digest();
              this._fingerprintHash = false;
              this._computedFingerprint = digest;
            } else if (chunk.id === ChunkIds.Data) {
              if (!this._headerReadCompleted) {
                this._headerReadCompleted = true;
                this._readerHandlers.headerComplete();
              }
              if (!this._dataReadReady) {
                this._pendingChunks.push(chunk);
              } else {
                const paused = !this._asnReader.isPaused();
                if (paused) {
                  this._asnReader.pause();
                }
                this.processDataChunk(chunk as Asn1DataChunk)
                  .finally(() => {
                    if (paused) {
                      this._asnReader.resume();
                    }
                  });
              }
            }
            if (chunk.id != ChunkIds.Data) {
              if (Asn1EncryptedChunk.isInstance(chunk)) {
                this._pendingChunks.push(chunk);
              } else {
                this._onReadChunk(chunk);
              }
            }
          } while (0);
        }
        this._asnSequence++;
      })
      .on('end-sequence', (result: Asn1SequenceResult) => {
      });
  }

  private _updateFingerprintPayload(data: Buffer) {
    if (this._fingerprintHash === false)
      return ;
    if (this._fingerprintHash) {
      this._fingerprintHash.update(data);
    } else {
      this._fingerprintPending.push(data);
    }
  }

  private _onReadChunk(chunk: Asn1ObjectChunk) {
    this._chunks.set(chunk.id, chunk);
    if (chunk.id >= ChunkIds.CustomBegin) {
      const chunkImpl = chunk as Asn1CustomDataChunk;
      let flags = 0;
      if (chunk.flags.encryptWithAuthKey) {
        flags |= CustomChunkFlags.ENCRYPT_WITH_AUTH_KEY;
      }
      this._readerHandlers.pushCustomChunk(new CustomChunk(
        chunk.id - ChunkIds.CustomBegin,
        flags,
        arrayBufferToBuffer(chunkImpl.data.valueBlock.valueHex)
      ));
    }
  }

  private _createAuthKeyDecipher() {
    const crypto = cryptoUtils.createCipher({
      oid: this._defaultHeaderChunk.chunkCryptoAlgorithm.valueBlock.toString(),
      key: this._authEncryptKey,
      iv: this._authKeyCryptoIv
    });
    return crypto.createDecipher();
  }

  processDataChunk(chunk: Asn1DataChunk): Promise<boolean> {
    const data = chunk.getData();
    if (this._dataMac) {
      this._dataMac.update(data);
    }
    const decrypted = this._dataDecipher.update(data);
    if (decrypted) {
      return this._readerHandlers.push(decrypted);
    }
    return Promise.resolve(true);
  }

  public final(callback: (err: any) => void) {
    if (!this._dataReadReady) {
      callback(new Error('data read not ready'));
      return ;
    }

    const macOfEncryptedDataChunk = this._chunks.get(Asn1MacOfEncryptedDataChunk.CHUNK_ID) as Asn1MacOfEncryptedDataChunk;
    if (this._dataCryptoAlgorithm.isGcmMode) {
      this._dataDecipher.setAuthTag(macOfEncryptedDataChunk.getData());
    } else if (this._dataMac) {
      const mac = this._dataMac.digest();
    }

    try {
      const decrypted = this._dataDecipher.final();
      if (decrypted) {
        this._readerHandlers.push(decrypted);
      }
    } catch (e) {
      callback(new ValidateFailedError('data mac not correct'));
      return;
    }

    const fingerprintChunk = this._chunks.get(Asn1FingerprintChunk.CHUNK_ID) as Asn1FingerprintChunk;
    if (!fingerprintChunk.getData().equals(this._computedFingerprint)) {
      callback(new ValidateFailedError('fingerprint not correct'));
      return;
    }

    if (this._operationType.isSign()) {
      const signedFingerprintChunk = this._chunks.get(Asn1SignedFingerprintChunk.CHUNK_ID) as Asn1SignedFingerprintChunk;
      if (!this[S_asymKey].verify(
        this._defaultHeaderChunk.fingerprintAlgorithm,
        this._computedFingerprint,
        signedFingerprintChunk.getData()
      )) {
        callback(new ValidateFailedError('fingerprint signature not correct'));
      }
    }

    callback(null);
  }

  public init(params: IExactReaderInitParams): Promise<any> {
    const authKeyCheckChunk = this._chunks.get(ChunkIds.AuthKeyCheckData) as Asn1AuthKeyCheckChunk;
    if (!checkAuthKey(authKeyCheckChunk, params.authKey)) {
      return Promise.reject(new Error('authKey is not correct'));
    }

    this[S_asymKey] = params.key;

    this._defaultHeaderChunk = this._chunks.get(ChunkIds.DefaultHeader) as Asn1DefaultHeaderChunk;
    const authKeyDerivationPool = rfc5869(params.authKey, 'sha256', 64);
    this._authEncryptKey = authKeyDerivationPool.slice(0, 32);
    this._authMacKey = authKeyDerivationPool.slice(32, 64);
    this._authKeyCryptoIv = arrayBufferToBuffer(this._defaultHeaderChunk.authKeyCryptionIv.valueBlock.valueHex);

    const pendingDataChunks: Asn1DataChunk[] = [];

    let chunk;
    while ((chunk = this._pendingChunks.shift())) {
      if (Asn1EncryptedChunk.isInstance(chunk)) {
        const chunkImpl = chunk as Asn1EncryptedChunk;
        const cipher = this._createAuthKeyDecipher();
        const decryptedData = Buffer.concat([
          cipher.update(arrayBufferToBuffer(chunkImpl.getChunkData().valueBlock.valueHex)),
          cipher.final()
        ]);
        const decrypted = chunkImpl.getDecryptedChunk(decryptedData);
        this._onReadChunk(decrypted);
      } else {
        pendingDataChunks.push(chunk as Asn1DataChunk);
      }
    }

    let dataKeyInfoChunk: Asn1DataKeyInfoChunk | null = null;
    let dataCryptoKey: Buffer | null = null;
    let dataMacKey: Buffer | null = null;
    if (this._operationType.isSign()) {
      dataKeyInfoChunk = this._chunks.get(Asn1DataKeyInfoChunk.CHUNK_ID) as Asn1DataKeyInfoChunk;
    }
    if (this._operationType.isPublicEncrypt()) {
      if (params.key.privateDecryptable) {
        const encryptedDataKeyInfo = this._chunks.get(Asn1EncryptedDataKeyInfoChunk.CHUNK_ID) as Asn1EncryptedDataKeyInfoChunk;
        const decryptedData = params.key.privateDecrypt(encryptedDataKeyInfo.getData());
        dataKeyInfoChunk = Asn1DataKeyInfoChunk.decodeChunkData(
          encryptedDataKeyInfo.id, encryptedDataKeyInfo.flags.value,
          decryptedData
        ) as Asn1DataKeyInfoChunk;
      } else {
        const ecPublicKeyChunk = this._chunks.get(Asn1EphemeralECPublicKeyChunk.CHUNK_ID) as Asn1EphemeralECPublicKeyChunk;
        const dhCheckDataChunk = this._chunks.get(Asn1DHCheckDataChunk.CHUNK_ID) as Asn1DHCheckDataChunk;
        const publicKey = cc.createAsymmetricKey({
          key: ecPublicKeyChunk.data.toSchema().toBER(),
          format: 'der',
          type: 'spki'
        });
        const ecdh = params.key.dhComputeSecret(publicKey);
        const hkdfResult = hkdfCompute({
          nodeAlgorithm: 'sha256',
          master: ecdh,
          length: 96,
          salt: Buffer.alloc(0)
        });
        dataCryptoKey = hkdfResult.output.slice(0, 32);
        dataMacKey = hkdfResult.output.slice(32, 64);
        const computedDhCheckData = hkdfResult.output.slice(64, 96);
        if (!dhCheckDataChunk.equals(computedDhCheckData)) {
          return Promise.reject(new Error('wrong key'));
        }
      }
    }
    if (dataKeyInfoChunk) {
      if (!dataKeyInfoChunk.validate()) {
        return Promise.reject(new Error('Wrong key'));
      }
      dataCryptoKey = arrayBufferToBuffer(dataKeyInfoChunk.dataKey.valueBlock.valueHex);
      dataMacKey = arrayBufferToBuffer(dataKeyInfoChunk.macKey.valueBlock.valueHex);
    }
    if (!dataCryptoKey || !dataMacKey) {
      return Promise.reject('Unknown error');
    }

    const dataCryptoAlgorithmChunk = this._chunks.get(Asn1DataCryptoAlgorithmSpecChunk.CHUNK_ID) as Asn1DataCryptoAlgorithmSpecChunk;
    const dataCryptoAlgorithm = cryptoUtils.createCipher({
      oid: this._defaultHeaderChunk.dataCryptoAlgorithm.valueBlock.toString(),
      key: dataCryptoKey,
      parameterSpec: dataCryptoAlgorithmChunk.data
    });
    this._dataCryptoAlgorithm = dataCryptoAlgorithm;
    this._dataDecipher = dataCryptoAlgorithm.createDecipher();
    if (dataCryptoAlgorithm.isGcmMode) {
      this._dataDecipher.setAAD(dataMacKey);
    } else {
      this._dataMac = null;
    }
    this._dataReadReady = true;

    return pendingDataChunks.reduce(
      (prev, cur) => prev.then(
        () => {
          return this.processDataChunk(cur);
        }
      ), Promise.resolve(true)
    );
  }

  parse(readBuffer: ReadBuffer): Promise<ParseResult> {
    return new Promise<ParseResult>((resolve, reject) => {
      try {
        const buf = readBuffer.readRemainingBuffer();
        this._asnReader.write(buf, () => {
          resolve(ParseResult.NEED_MORE);
        });
      } catch (e) {
        reject(e);
      }
    });
  }
}
