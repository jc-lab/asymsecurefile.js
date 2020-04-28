import * as fs from 'fs';
import MockFs from 'mock-fs';
import * as uuids from 'uuid';

import * as cc from 'commons-crypto';
import * as AsymSecureFile from "../src";
import {CustomChunk} from "../src";

const USE_MOCK_FILESYSTEM = process.env.USE_MOCK_FILESYSTEM || true;
const OUTPUT_ROOT_PATH = process.env.OUTPUT_ROOT_PATH || '';
const USE_CONSOLE_OUTPUT = process.env.USE_CONSOLE_OUTPUT || false;

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

describe('EC Key Test', function () {
  const priKey = cc.createAsymmetricKey({
    key: `-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgfs82+aZk5zFjAGhT4tO1
q4Mg7Lw3Y3okG1JQzR5Q9wKhRANCAASdmnZ/+ISGZIAPxduEQR/MxzW6epL9zH8/
k0Yn7DPLJiFa5rYZhA62+9jVqGiORPvWWvLvzG7RsjItUFEh8KnI
-----END PRIVATE KEY-----`
  });
  const pubKey = cc.createAsymmetricKey({
    key: `-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEnZp2f/iEhmSAD8XbhEEfzMc1unqS/cx/
P5NGJ+wzyyYhWua2GYQOtvvY1ahojkT71lry78xu0bIyLVBRIfCpyA==
-----END PUBLIC KEY-----`
  });

  it('sign', async function () {
    this.timeout(10000);
    const filePath = MOCK_ROOT_PATH + '/ec-sign.jasf';
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
          await reader.init({
            authKey: '1234'
          });
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
    const filePath = MOCK_ROOT_PATH + '/ec-pe.jasf';
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
          await reader.init({
            authKey: '1234'
          });
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
