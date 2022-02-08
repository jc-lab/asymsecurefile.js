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

const expectThrowsAsync = async (method: any, errorMessage?: string) => {
  let error: any = null
  try {
    await method()
  }
  catch (err) {
    error = err
  }
  expect(error).to.be.an('Error')
  if (errorMessage) {
    expect(error.message).to.equal(errorMessage)
  }
}

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
  (global as any).Promise = function (func) {
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

describe('Other usages', function () {
  const ecPriKey = cc.createAsymmetricKey({
    key: `-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgfs82+aZk5zFjAGhT4tO1
q4Mg7Lw3Y3okG1JQzR5Q9wKhRANCAASdmnZ/+ISGZIAPxduEQR/MxzW6epL9zH8/
k0Yn7DPLJiFa5rYZhA62+9jVqGiORPvWWvLvzG7RsjItUFEh8KnI
-----END PRIVATE KEY-----`
  });
  const ecPubKey = cc.createAsymmetricKey({
    key: `-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEnZp2f/iEhmSAD8XbhEEfzMc1unqS/cx/
P5NGJ+wzyyYhWua2GYQOtvvY1ahojkT71lry78xu0bIyLVBRIfCpyA==
-----END PUBLIC KEY-----`
  });

  it('read custom chunk before set Asym Key', async function () {
    this.timeout(10000);
    const filePath = MOCK_ROOT_PATH + '/ec-sign.jasf';
    await new Promise((resolve, reject) => {
      const fos = fs.createWriteStream(filePath);
      const writer = new AsymSecureFile.Writer({
        operationType: AsymSecureFile.OperationType.SIGN,
        excludeHeader: false,
        version: 4,
        authKey: '1234',
        key: ecPriKey,
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

    let readChunks: Record<number, Buffer> = {};

    await new Promise((resolve, reject) => {
      const fis = fs.createReadStream(filePath);
      const reader = new AsymSecureFile.Reader({
        authKey: '1234'
      });
      reader
        .on('header-complete', (next) => {
          if(USE_CONSOLE_OUTPUT) {
            console.log('EVENT: header-complete');
            console.log('HeaderComplete: custom-chunk 0x01 : ', reader.getCustomChunk(0x01));
            console.log('HeaderComplete: custom-chunk 0x02 : ', reader.getCustomChunk(0x02));
          }
          reader.init({
            key: ecPubKey
          })
            .then(() => next())
            .catch(e => reject(e));
        })
        .on('custom-chunk', (chunk: AsymSecureFile.CustomChunk) => {
          if(USE_CONSOLE_OUTPUT) {
            console.log('EVENT: custom-chunk : ' + chunk.id + ' : ' + chunk.data.toString());
          }
          readChunks[chunk.id] = chunk.data;
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
        })
    });
    expect(readChunks[1]).to.eql(Buffer.from('I_AM_NORMAL-1'));
    expect(readChunks[2]).to.eql(Buffer.from('I_AM_SECRET-1'));
  });
});
