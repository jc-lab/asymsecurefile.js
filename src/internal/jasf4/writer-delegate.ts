import * as crypto from 'crypto';

import axios from 'axios';
import * as asn1js from 'asn1js';
import * as cc from 'commons-crypto';
import * as cryptoUtils from '../crypto-utils';

import {
  CustomChunk
} from '../../common';
import {
  IWriterHandlers,
  WriterDelegate
} from '../writer-delegate';
import {
  IExactWriterParams,
  JASF_FILE_HEADER,
  rfc5869
} from '../intl';
import {
  FORMAT_VERSION,
  makeAuthKeyCheck
} from './jasf4-common';
import OrderSafety from '../order-safety';
import {
  CustomChunkFlags
} from '../../custom-chunk';
import {
  arrayBufferToBuffer,
  bufferToArrayBuffer
} from '../asn-utils';
import {
  Asn1AsymAlgorithmIdentifierChunk,
  Asn1ChunkFlags,
  Asn1CustomDataChunk,
  Asn1DataChunk,
  Asn1DataCryptoAlgorithmSpecChunk,
  Asn1DataKeyInfoChunk,
  Asn1DataMacAlgorithmSpecChunk,
  Asn1DefaultHeaderChunk, Asn1DHCheckDataChunk,
  Asn1EncryptedChunk,
  Asn1EncryptedDataKeyInfoChunk, Asn1EphemeralECPublicKeyChunk,
  Asn1FingerprintChunk,
  Asn1MacOfEncryptedDataChunk,
  Asn1ObjectChunk,
  Asn1SignedFingerprintChunk,
  Asn1TimestampChunk
} from './asn-objects';
import {
  hkdfCompute
} from '../crypto-utils';
import AlgorithmIdentifier from 'pkijs/build/AlgorithmIdentifier';
import PublicKeyInfo from 'pkijs/build/PublicKeyInfo';
import TimeStampReq from 'pkijs/build/TimeStampReq';
import MessageImprint from 'pkijs/build/MessageImprint';
import TimeStampResp from 'pkijs/build/TimeStampResp';
import {
  AsymmetricAlgorithmType
} from 'commons-crypto';

enum WriteState {
  INITIALIZEING,
  WRITEING_HEADER,
  WRITEING_DATA,
}

function makeAsymAlgorithmParamChunk(key: cc.AsymmetricKeyObject): Asn1AsymAlgorithmIdentifierChunk {
  let algorithmIdentifier;
  let ber;

  do {
    if (key.isPrivate()) {
      try {
        ber = bufferToArrayBuffer(key.export({
          type: 'pkcs8',
          format: 'der'
        }));
        const {result} = asn1js.fromBER(ber);
        const privateKeyInfo = new cc.asn.PrivateKeyInfo({
          schema: result
        });

        algorithmIdentifier = privateKeyInfo.privateKeyAlgorithm;
        break;
      } catch (e) {
        console.error(e);
        // empty
      }
    }
    if (key.isPublic()) {
      try {
        ber = bufferToArrayBuffer(key.export({
          type: 'spki',
          format: 'der'
        }));
        const {result} = asn1js.fromBER(ber);
        const publicKeyInfo = new PublicKeyInfo({
          schema: result
        });

        algorithmIdentifier = publicKeyInfo.algorithm;
        break;
      } catch (e) {
        console.error(e);
        // empty
      }
    }
  } while (0);

  if (!algorithmIdentifier) {
    throw new Error('Unknown key format');
  }
  return Asn1AsymAlgorithmIdentifierChunk.create(algorithmIdentifier);
}

export class Jasf4WriterDelegate implements WriterDelegate {
  private _props: IExactWriterParams;
  private _handlers: IWriterHandlers;
  private _writeState: WriteState = WriteState.INITIALIZEING;

  private _asymKey: cc.AsymmetricKeyObject;

  private _safeWrite: OrderSafety = new OrderSafety();

  private _authEncryptKey: Buffer;
  private _authMacKey: Buffer;

  private _fingerprintHash: crypto.Hash | null;
  private _dataCryptoAlgorithm!: cryptoUtils.ICreateCipherResult;
  private _dataCipher!: crypto.CipherGCM;
  private _dataMac: crypto.Hmac | null = null;

  private _chunkCryptoAlgorithm: asn1js.ObjectIdentifier = new asn1js.ObjectIdentifier({
    value: '2.16.840.1.101.3.4.1.42'
  });
  private _fingerprintAlgorithm: asn1js.ObjectIdentifier = new asn1js.ObjectIdentifier({
    value: '2.16.840.1.101.3.4.2.1'
  });
  private _authKeyCryptoIv!: Buffer;

  constructor(handlers: IWriterHandlers, props: IExactWriterParams) {
    this._handlers = handlers;
    this._props = props;

    const authKeyDerivationPool = rfc5869(props.authKey, 'sha256', 64);
    this._authEncryptKey = authKeyDerivationPool.slice(0, 32);
    this._authMacKey = authKeyDerivationPool.slice(32, 64);

    this._fingerprintHash = crypto.createHash('sha256');

    this._asymKey = props.key;
  }

  _writePayload (chunk: Buffer): Promise<boolean> {
    if (this._fingerprintHash) {
      this._fingerprintHash.update(chunk);
    }
    return this._handlers.push(chunk);
  }

  _writeFileHeaderSignature (): Promise<any> {
    if (!this._props.excludeHeader) {
      return this._handlers.push(Buffer.concat([JASF_FILE_HEADER, Buffer.from([ FORMAT_VERSION ])]));
    }
    return Promise.resolve();
  }

  _writeFileHeaderPayload (): Promise<any> {
    const versionPayload = new asn1js.Integer({
      value: FORMAT_VERSION
    }).toBER();
    const operationTypePayload = new asn1js.Enumerated({
      value: this._props.operationType.value
    }).toBER();
    return this._writePayload(Buffer.concat([
      Buffer.from([0x30, 0x80]),
      arrayBufferToBuffer(versionPayload),
      arrayBufferToBuffer(operationTypePayload)
    ]));
  }

  _encryptChunk (object: Asn1ObjectChunk): Promise<Asn1EncryptedChunk> {
    const crypto = cryptoUtils.createCipher({
      oid: this._chunkCryptoAlgorithm.valueBlock.toString(),
      key: this._authEncryptKey,
      iv: this._authKeyCryptoIv
    });
    const cipher = crypto.createCipher();
    const encrypted = Buffer.concat([
      cipher.update(arrayBufferToBuffer(object.getChunkData().toBER())),
      cipher.final()
    ]);
    return Promise.resolve(
      Asn1EncryptedChunk.create(
        object.id,
        object.flags.value,
        encrypted
      )
    );
  }

  _writeChunk (object: Asn1ObjectChunk): Promise<boolean> {
    if (!Asn1EncryptedChunk.isInstance(object)) {
      if (object.flags.encryptWithAuthKey) {
        return this._encryptChunk(object)
          .then(encryptedObject => this._writePayload(
            arrayBufferToBuffer(encryptedObject.toBER())
          ));
      }
    }
    return this._writePayload(arrayBufferToBuffer(object.toBER()));
  }

  private _writeCustomChunk(customChunk: CustomChunk): Promise<any> {
    const flags = Asn1ChunkFlags.create();
    flags.encryptWithAuthKey = customChunk.hasFlag(CustomChunkFlags.ENCRYPT_WITH_AUTH_KEY);
    const chunk = Asn1CustomDataChunk.create(
      customChunk.id,
      flags,
      customChunk.data
    );
    return this._writeChunk(chunk);
  }

  private _writeDataChunk(data: Buffer): Promise<any> {
    const chunk = Asn1DataChunk.create(data);
    return this._writeChunk(chunk);
  }

  private _writeData(data: Buffer): Promise<any> {
    const cipherText = this._dataCipher.update(data);
    if (cipherText && cipherText.length > 0) {
      if (this._dataMac) {
        this._dataMac.update(cipherText);
      }
      return this._writeDataChunk(cipherText);
    }
    return Promise.resolve();
  }

  private _writeFinalData(): Promise<any> {
    const cipherText = this._dataCipher.final();
    return (() => {
      if (cipherText && cipherText.length > 0) {
        if (this._dataMac) {
          this._dataMac.update(cipherText);
        }
        return this._writeDataChunk(cipherText);
      }
      return Promise.resolve();
    })()
      .then((): Promise<any> => {
        if (this._dataMac) {
          const digest = this._dataMac.digest();
          return this._writeChunk(
            Asn1MacOfEncryptedDataChunk.create(digest)
          );
        } else if (this._dataCryptoAlgorithm.isGcmMode) {
          return this._writeChunk(
            Asn1MacOfEncryptedDataChunk.create(this._dataCipher.getAuthTag())
          );
        }
        return Promise.resolve();
      });
  }

  private _writeFooter(): Promise<any> {
    const fingerprint = (this._fingerprintHash as crypto.Hash).digest();
    const fingerprintChunk = Asn1FingerprintChunk.create(fingerprint);
    this._fingerprintHash = null;
    return this._writeChunk(fingerprintChunk)
      .then((): Promise<any> => {
        if (this._props.operationType.isSign()) {
          const signature = this._asymKey.sign(this._fingerprintAlgorithm, fingerprint);
          return this._writeChunk(
            Asn1SignedFingerprintChunk.create(signature)
          );
        }
        return Promise.resolve();
      })
      .then((): Promise<any> => {
        if (this._props.tsaLocation) {
          const timeout = 3000;
          const tsReq = new TimeStampReq({
            certReq: true,
            nonce: new asn1js.Integer({
              valueHex: bufferToArrayBuffer(crypto.randomBytes(8))
            } as any),
            messageImprint: new MessageImprint({
              hashAlgorithm: new AlgorithmIdentifier({
                algorithmId: this._fingerprintAlgorithm.valueBlock.toString()
              }),
              hashedMessage: new asn1js.OctetString({
                valueHex: fingerprint
              })
            })
          });
          const tsReqPayload = arrayBufferToBuffer(tsReq.toSchema().toBER());
          const cancelCtx: {
            resolved: boolean,
            exec: any,
            timeout: any,
            done: () => void
          } = {
            resolved: false,
            exec: null,
            timeout: setTimeout(() => {
              if (cancelCtx.exec) {
                cancelCtx.exec();
              }
            }, timeout),
            done: () => {
              cancelCtx.resolved = true;
              if (cancelCtx.timeout) {
                clearTimeout(cancelCtx.timeout);
              }
            }
          };
          return axios.post(this._props.tsaLocation, tsReqPayload, {
            headers: {
              'content-type': 'application/timestamp-query',
              'user-agent': 'jasf client node.js'
            },
            responseType: 'arraybuffer',
            timeout: timeout,
            cancelToken: new axios.CancelToken(c => cancelCtx.exec = c)
          }).then(httpResponse => {
            cancelCtx.done();
            const asn = asn1js.fromBER(bufferToArrayBuffer(httpResponse.data));
            const tsResp = new TimeStampResp({
              schema: asn.result
            });
            return this._writeChunk(
              Asn1TimestampChunk.create(
                tsResp.timeStampToken
              )
            );
          }).catch(e => {
            cancelCtx.done();
            this._handlers.emitError(e);
          });
        }
        return Promise.resolve();
      })
      .then(() => this._writePayload(Buffer.from([0x00, 0x00])));
  }

  init(): Promise<void> {
    return this._safeWrite
      .run(() => {
        if (this._writeState > WriteState.INITIALIZEING) {
          return Promise.resolve();
        }

        const authKeycheckDataObject = makeAuthKeyCheck(this._props.authKey);

        this._authKeyCryptoIv = crypto.randomBytes(16);

        let asymAlgorithmType: cc.AsymmetricAlgorithmType = this._props.key.getKeyAlgorithm().type;
        let asymAlgorithmParamChunk: Asn1AsymAlgorithmIdentifierChunk | null;
        let dataCryptoAlgorithmParamChunk: Asn1DataCryptoAlgorithmSpecChunk | null = null;
        let dataMacAlgorithm: AlgorithmIdentifier | null = null;

        if (this._props.key.getKeyAlgorithm().type === AsymmetricAlgorithmType.ec) {
          asymAlgorithmParamChunk = makeAsymAlgorithmParamChunk(this._props.key);
        }

        const dataIv = crypto.randomBytes(16);
        let dataCryptoKey: Buffer;
        let dataMacKey: Buffer | null = null;

        let dataKeyInfo: Asn1DataKeyInfoChunk | null = null;
        let encryptedDataKeyInfo: Asn1EncryptedDataKeyInfoChunk | null = null;

        let ecPublicKeyChunk: Asn1EphemeralECPublicKeyChunk | null = null;
        let dhCheckDataChunk: Asn1DHCheckDataChunk | null = null;

        if (this._props.operationType.isSign() || this._props.key.publicEncryptable) {
          dataCryptoKey = crypto.randomBytes(32);
          dataMacKey = crypto.randomBytes(32);
          dataKeyInfo = Asn1DataKeyInfoChunk.create(
            dataCryptoKey,
            dataMacKey
          );

          if (this._props.operationType.isPublicEncrypt()) {
            const plaintext = arrayBufferToBuffer(dataKeyInfo.getChunkData().toBER());
            encryptedDataKeyInfo = Asn1EncryptedDataKeyInfoChunk.create(
              this._props.key.publicEncrypt(plaintext)
            );
          }
        }
        else {
          const algorithm = this._props.key.getKeyAlgorithm();
          const { privateKey, publicKey } = algorithm.generateKeyPair();
          const ecdh = privateKey.dhComputeSecret(this._props.key);
          const hkdfResult = hkdfCompute({
            nodeAlgorithm: 'sha256',
            master: ecdh,
            length: 96,
            salt: Buffer.alloc(0)
          });
          dataCryptoKey = hkdfResult.output.slice(0, 32);
          dataMacKey = hkdfResult.output.slice(32, 64);
          ecPublicKeyChunk = Asn1EphemeralECPublicKeyChunk.create(
            publicKey.export({
              type: 'spki',
              format: 'der'
            })
          );
          dhCheckDataChunk = Asn1DHCheckDataChunk.create(
            hkdfResult.output.slice(64, 96)
          );
        }

        const dataCryptoAlgorithm = cryptoUtils.createCipher({
          nodeAlgorithm: this._props.operationType.isPublicEncrypt() ? 'aes-256-gcm' : 'aes-256-cbc',
          key: dataCryptoKey,
          iv: dataIv
        });
        this._dataCryptoAlgorithm = dataCryptoAlgorithm;

        if (dataCryptoAlgorithm.parameterSpec) {
          dataCryptoAlgorithmParamChunk = Asn1DataCryptoAlgorithmSpecChunk.create(
            dataCryptoAlgorithm.parameterSpec
          );
        }

        this._dataCipher = dataCryptoAlgorithm.createCipher();
        if (this._props.operationType.isPublicEncrypt()) {
          if (dataCryptoAlgorithm.isGcmMode) {
            dataMacAlgorithm = new AlgorithmIdentifier({
              algorithmId: '1.0.9797.3.4'
            });
            this._dataCipher.setAAD(dataMacKey);
          } else {
            dataMacAlgorithm = new AlgorithmIdentifier({
              algorithmId: '1.2.840.113549.2.9'
            });
            this._dataMac = crypto.createHmac('sha256', dataMacKey);
          }
        }

        return this._writeFileHeaderSignature()
          .then(() => this._writeFileHeaderPayload())
          .then(() => this._writeChunk(Asn1DefaultHeaderChunk.create(
            1,
            asymAlgorithmType,
            this._chunkCryptoAlgorithm,
            new asn1js.ObjectIdentifier({
              value: dataCryptoAlgorithm.oid
            }),
            this._fingerprintAlgorithm,
            this._authKeyCryptoIv
          )))
          .then(() => this._writeChunk(authKeycheckDataObject))
          .then(() => asymAlgorithmParamChunk ? this._writeChunk(asymAlgorithmParamChunk) : Promise.resolve(true))
          .then(() => dataCryptoAlgorithmParamChunk ? this._writeChunk(dataCryptoAlgorithmParamChunk) : Promise.resolve(true))
          .then(() => ecPublicKeyChunk ? this._writeChunk(ecPublicKeyChunk) : Promise.resolve(true))
          .then(() => dhCheckDataChunk ? this._writeChunk(dhCheckDataChunk) : Promise.resolve(true))
          .then(() => dataMacAlgorithm ? this._writeChunk(
            Asn1DataMacAlgorithmSpecChunk.create(dataMacAlgorithm)
          ) : Promise.resolve(true))
          .then(() => encryptedDataKeyInfo ? this._writeChunk(encryptedDataKeyInfo) : dataKeyInfo ? this._writeChunk(dataKeyInfo) : Promise.resolve(true))
          .then(() => {
            this._writeState = WriteState.WRITEING_HEADER;
          });
      });
  }

  addCustomChunk(chunk: CustomChunk): Promise<void> {
    return this.init()
      .then(() => this._safeWrite.run(() => {
        if (this._writeState >= WriteState.WRITEING_DATA) {
          return Promise.reject(new Error('Not allow after data chunk'));
        }
        return this._writeCustomChunk(chunk);
      }));
  }

  write(chunk: Buffer, callback: (err: any) => void) {
    return this.init()
      .then(() =>
        this._safeWrite.run(() => {
          return this._writeData(chunk)
            .then(() => callback(null))
            .catch(err => callback(err));
        })
      );
  }


  final(callback: (err: any) => void) {
    return this.init()
      .then(() => this._writeFinalData())
      .then(() => this._writeFooter())
      .then(() => callback(null))
      .catch(err => callback(err));
  }
}
