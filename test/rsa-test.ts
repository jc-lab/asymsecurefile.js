import * as fs from 'fs';
import MockFs from 'mock-fs';
import * as uuids from 'uuid';

import * as cc from 'commons-crypto';
import * as AsymSecureFile from "../src";
import {CustomChunk} from "../src";

function toBoolean(s: string | undefined, defaultValue: boolean): boolean | undefined {
  if (typeof s === 'undefined')
    return defaultValue;
  return /true|1|yes/i.test(s);
}

const USE_MOCK_FILESYSTEM = toBoolean(process.env.USE_MOCK_FILESYSTEM, true);
const OUTPUT_ROOT_PATH = process.env.OUTPUT_ROOT_PATH || '';
const USE_CONSOLE_OUTPUT = toBoolean(process.env.USE_CONSOLE_OUTPUT, false);

const chai = require('chai');
const expect = chai.expect;
const assert = chai.assert;
const should = chai.should();

if(false) {
  function arrayArguments(input: IArguments): any[] {
    const arr: any[] = [];
    for(let item of input) {
      arr.push(item);
    }
    return arr;
  }

  // promise debug
  const promiseMap: Map<string, any> = new Map();
  const OrigPromise: PromiseConstructor = global.Promise as PromiseConstructor;
  global.Promise = function (func) {
    const stack = new Error().stack;
    return new OrigPromise((resolve, reject) => {
      const uuid = uuids.v4();
      promiseMap.set(uuid, {
        uuid,
        stack
      });
      func(function() {
        promiseMap.delete(uuid);
        resolve.call(null, ...arrayArguments(arguments));
      }, (err) => {
        promiseMap.delete(uuid);
        reject(err);
      });
    });
  }
  function showPendingPromise() {
    for(let item of promiseMap.entries()) {
      console.log(item[1]);
    }
  }
  Object.keys(OrigPromise).forEach(v => {
    global.Promise[v] = OrigPromise[v];
  });
  global.Promise['resolve'] = OrigPromise.resolve;
  global.Promise['reject'] = OrigPromise.reject;
}

const MOCK_ROOT_PATH = USE_MOCK_FILESYSTEM ? '' : OUTPUT_ROOT_PATH;

if(USE_MOCK_FILESYSTEM) {
  beforeEach(() => {
    MockFs();
  })

  afterEach(() => {
    MockFs.restore();
  })
}

describe('RSA Key Test', function () {
  const priKey = cc.createAsymmetricKey({
    key: `-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCz764g9Dr4ZXQDEw8+Il2mbWQ5ACInIBklISsqBmAh5SbnZkqv
cuZ6aj69AHV7IhrDujm730daSH8+wZjHV011V8/sSdK4qvvX0bRql3YUTNQbsBDj
PaV8RRHqHEw/NobbeqtX8QIRvF4eeRyjmLodI1G0N1JinKuM1XYpyKvqlQIDAQAB
AoGAO0CI+acTKCrYag7DrTVJ230YTMDjfjjOrvBeM2eIDoFUL0z6+Q2AIf2MjVZy
WUrgv2U6j8g1yeAnrrW3pqT0B0tQGYYAtAELNe2VZbBBVYQOUS53kq3VowYYMM3z
8R2rEmZTsreFT6uq9+9RMtm5W9ugti//BMte5T8JP5o0l10CQQDntf/ieUmndkGr
t55ROUZZOZJmjr5CTELvjbwnFDx50qh6b1Tzld6l/Gps2b+KxcVswM86Q25PAnbx
VP/rmWoTAkEAxsxMcIcvuDes5A2UcVU7TiyYAsO9vVEfqtDDff50PXd/xNa7ICe0
VtJmVazm8B5K6fVh0Z3EUNff+lRyz61ttwJATmI5D8nr6qSMjqRtABkZ/TEGn38G
SbM2qYcO8UFdO/DRYamr2UMHsKr07aGztCQ3JxUKhTEubbftuLICaRba1QJAfxYL
p8REVVgCRqgHxYvfJdKMOvg3S9eYjvJ2hw0r8j96hrNfXOcE+pv2n76ww8AZ1Aby
Sba50ZSvsrBZ1TnhcQJBAK/jKY+AXaACpoPrradRA80S+WEq8L10o7UYFPxgDdcN
s2QyKSJ2+ZiRXRFpd7L3j6REj+YELpq+10s5lvkgbyU=
-----END RSA PRIVATE KEY-----`
  });
  const pubKey = cc.createAsymmetricKey({
    key: `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCz764g9Dr4ZXQDEw8+Il2mbWQ5
ACInIBklISsqBmAh5SbnZkqvcuZ6aj69AHV7IhrDujm730daSH8+wZjHV011V8/s
SdK4qvvX0bRql3YUTNQbsBDjPaV8RRHqHEw/NobbeqtX8QIRvF4eeRyjmLodI1G0
N1JinKuM1XYpyKvqlQIDAQAB
-----END PUBLIC KEY-----`
  });

  it('sign', async function () {
    this.timeout(10000);
    const filePath = MOCK_ROOT_PATH + '/rsa-sign.jasf';
    await new Promise((resolve, reject) => {
      const fos = fs.createWriteStream(filePath);
      const writer = new AsymSecureFile.Writer({
        operationType: AsymSecureFile.OperationType.SIGN,
        excludeHeader: false,
        version: 4,
        authKey: '1234',
        key: priKey,
        // key: crypto.createPrivateKey(keypair.privateKey),
        // key: crypto.createPublicKey(keypair.publicKey),
        // tsaLocation: 'http://tsa.starfieldtech.com'
      });
      writer.on('error', (e) => {
        reject(e);
      }).pipe(fos)
        .on('close', () => {
          resolve();
        }).on('error', (e) => {
        reject(e);
      });

      writer.init();
      writer.addCustomChunk(CustomChunk.builder()
        .id(0x1)
        .data(Buffer.from("I_AM_NORMAL-1"))
        .build());
      writer.addCustomChunk(CustomChunk.builder()
        .id(0x2)
        .data(Buffer.from("I_AM_SECRET-1"))
        .encryptWithAuthKey()
        .build());
      writer.write("HELLO WORLD,");
      writer.write("I AM HAPPY");
      writer.end();
    });
    let totalReadData = '';
    await new Promise((resolve, reject) => {
      const fis = fs.createReadStream(filePath);
      const reader = new AsymSecureFile.Reader({
        key: pubKey
      });
      reader
        .on('header-complete', async () => {
          if(USE_CONSOLE_OUTPUT) {
            console.log('header-complete');
            console.log('custom-chunk 0x01 : ', reader.getCustomChunk(0x01));
            // console.log('custom-chunk 0x02 : ', reader.getCustomChunk(0x02)); // throw error
          }
          reader.init({
            authKey: '1234'
          })
            .then(() => {
              if(USE_CONSOLE_OUTPUT) {
                console.log('custom-chunk 0x02 : ', reader.getCustomChunk(0x02));
              }
            })
            .catch(e => reject(e));
          if(USE_CONSOLE_OUTPUT) {
            console.log('custom-chunk 0x02 : ', reader.getCustomChunk(0x02));
          }
        })
        .on('custom-chunk', (chunk: AsymSecureFile.CustomChunk) => {
          if(USE_CONSOLE_OUTPUT) {
            console.log('custom-chunk : ' + chunk.id + ' : ' + chunk.data.toString());
          }
        });
      fis.pipe(reader)
        .on('close', () => {
          resolve();
        })
        .on('error', (e) => {
          reject(e);
        })
        .on('data', (data) => {
          if(USE_CONSOLE_OUTPUT) {
            console.log("READ DATA : ", data.toString());
          }
          totalReadData += data.toString();
        })
    });
    expect(totalReadData).to.equals('HELLO WORLD,I AM HAPPY');
  });

  it('public encrypt', async function () {
    const filePath = MOCK_ROOT_PATH + '/rsa-pe.jasf';
    await new Promise((resolve, reject) => {
      const fos = fs.createWriteStream(filePath);
      const writer = new AsymSecureFile.Writer({
        operationType: AsymSecureFile.OperationType.PUBLIC_ENCRYPT,
        excludeHeader: false,
        version: 4,
        authKey: '1234',
        key: pubKey,
        // key: crypto.createPrivateKey(keypair.privateKey),
        // key: crypto.createPublicKey(keypair.publicKey),
        // tsaLocation: 'http://tsa.starfieldtech.com'
      });
      writer.pipe(fos)
        .on('close', () => {
          resolve();
        }).on('error', (e) => {
        reject(e);
      });

      writer.init();
      writer.addCustomChunk(CustomChunk.builder()
        .id(0x1)
        .data(Buffer.from("I_AM_NORMAL-1"))
        .build());
      writer.addCustomChunk(CustomChunk.builder()
        .id(0x2)
        .data(Buffer.from("I_AM_SECRET-1"))
        .encryptWithAuthKey()
        .build());
      writer.write("HELLO WORLD,");
      writer.write("I AM HAPPY");
      writer.end();
    });
    let totalReadData = '';
    await new Promise((resolve, reject) => {
      const fis = fs.createReadStream(filePath);
      const reader = new AsymSecureFile.Reader({
        key: priKey
      });
      reader
        .on('header-complete', async () => {
          if(USE_CONSOLE_OUTPUT) {
            console.log('header-complete');
            console.log('custom-chunk 0x01 : ', reader.getCustomChunk(0x01));
            // console.log('custom-chunk 0x02 : ', reader.getCustomChunk(0x02)); // throw error
          }
          reader.init({
            authKey: '1234'
          })
            .then(() => {
              if(USE_CONSOLE_OUTPUT) {
                console.log('custom-chunk 0x02 : ', reader.getCustomChunk(0x02));
              }
            })
            .catch(e => reject(e));
          if(USE_CONSOLE_OUTPUT) {
            console.log('custom-chunk 0x02 : ', reader.getCustomChunk(0x02));
          }
        })
        .on('custom-chunk', (chunk: AsymSecureFile.CustomChunk) => {
          if(USE_CONSOLE_OUTPUT) {
            console.log('custom-chunk : ' + chunk.id + ' : ' + chunk.data.toString());
          }
        });
      fis.pipe(reader)
        .on('close', () => {
          resolve();
        })
        .on('error', (e) => {
          reject(e);
        })
        .on('data', (data) => {
          if(USE_CONSOLE_OUTPUT) {
            console.log("READ DATA : ", data.toString())
          }
          totalReadData += data.toString();
        })
    });
    expect(totalReadData).to.equals('HELLO WORLD,I AM HAPPY');
  });
});
