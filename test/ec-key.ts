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

  it('sign and verify', async function () {
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
        .on('header-complete', (next) => {
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
              next();
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

  it('sign and verify failed with wrong auth key', async function () {
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
    expectThrowsAsync(() => new Promise((resolve, reject) => {
      const fis = fs.createReadStream(filePath);
      const reader = new AsymSecureFile.Reader({
        key: pubKey
      });
      reader
        .on('header-complete', (next) => {
          if(USE_CONSOLE_OUTPUT) {
            console.log('header-complete');
            console.log('custom-chunk 0x01 : ', reader.getCustomChunk(0x01));
            // console.log('custom-chunk 0x02 : ', reader.getCustomChunk(0x02)); // throw error
          }
          reader.init({
            authKey: '2222'
          })
            .then(() => {
              if(USE_CONSOLE_OUTPUT) {
                console.log('custom-chunk 0x02 : ', reader.getCustomChunk(0x02));
              }
              next();
            })
            .catch(e => {
              reader.destroy(e);
              reject(e);
            });
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
    }));
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
        .on('header-complete', (next) => {
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
              next();
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

  it('verify pre generated payload', async function () {
    this.timeout(10000);

    const payload = Buffer.from('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', 'base64');

    let totalReadData = '';
    await new Promise((resolve, reject) => {
      const reader = new AsymSecureFile.Reader({
        key: pubKey
      });
      reader
        .on('header-complete', (next) => {
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
              next();
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
        })
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
      reader.write(payload);
      reader.end(null);
    });
    expect(totalReadData).to.equals('HELLO WORLD,I AM HAPPY');
  });

  it('private decrypt pre generated payload', async function () {
    this.timeout(10000);

    const payload = Buffer.from('CpvYE5cfk+hrft8FcFQCBDCAAgEECgECMEECAQECAQAwOQIBAQIBAgYJYIZIAWUDBAEqBglghkgBZQMEAS4GCWCGSAFlAwQCAQQQmy0EdTaTJICnSkl8BjayozBTAgECAgEAMEswJwQQDOCBvuyQurQPFAdst+YSlQICD6ACASAwDAYIKoZIhvcNAgkFAAQgL8xu0FLNK2JB/GoFnPULyt+TEsidwxxnqdzcyOu2ugwwGAIBIQIBADAQBgcqhkjOPQIBBgUrgQQACjAdAgExAgEAMBUEEBiYAw2PMKjaBHdlr3mve5kCAQwwXgIBMwIBADBWMBAGByqGSM49AgEGBSuBBAAKA0IABC/ny84gWkh4z3g9ii8XhjQwOBwsDBDEpmeIiFK4yzVmirEHxKh9wa7Hl3uE3BGnBbMdpl21qX4v+7kK5PWfphIwKAIBOQIBAAQgxktdlnDApIZFRujL+z9X1gpQ6NzgQibrvQgQIFHEMjQwDwIBMgIBADAHBgUozEUDBDBYAgE0AgEBBFCC505gMUgv3mu21nDtH5oELsXi1JCq1qJy9xkVw3N0X2VI4/KlGPe0Fdhf7uzcm1dCtN6dwyiNgcwyOrmOL3Aons+TY1I5A0/T0mTvx1grxDAWAgIAgQIBAAQNSV9BTV9OT1JNQUwtMTAZAgIAggIBAQQQvXPuvLy8LGAkXQwk/FghzTAYAgFwAgEABBAG57+QyHwOl4k84Vl7OAKVMA4CAXACAQAEBtY25glWWTAUAgFyAgEABAyFFya7cAe1S/Z7Xe4wKAIBdgIBAAQg+K1OO3XewXjAZZ/47nqyg0bu1oGSFbmkTIzGfFxxlcgwggy5AgF5AgEAMIIMrwYJKoZIhvcNAQcCoIIMoDCCDJwCAQMxDzANBglghkgBZQMEAgEFADB4BgsqhkiG9w0BCRABBKBpBGcwZQIBAQYLYIZIAYb9bgEHFwQwMTANBglghkgBZQMEAgEFAAQg+K1OO3XewXjAZZ/47nqyg0bu1oGSFbmkTIzGfFxxlcgCBVaCHUG3GA8yMDIwMDUzMDA4MTg0MloCCEzFPejpW9p5oIIJyzCCBQAwggPooAMCAQICAQcwDQYJKoZIhvcNAQELBQAwgY8xCzAJBgNVBAYTAlVTMRAwDgYDVQQIEwdBcml6b25hMRMwEQYDVQQHEwpTY290dHNkYWxlMSUwIwYDVQQKExxTdGFyZmllbGQgVGVjaG5vbG9naWVzLCBJbmMuMTIwMAYDVQQDEylTdGFyZmllbGQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgLSBHMjAeFw0xMTA1MDMwNzAwMDBaFw0zMTA1MDMwNzAwMDBaMIHGMQswCQYDVQQGEwJVUzEQMA4GA1UECBMHQXJpem9uYTETMBEGA1UEBxMKU2NvdHRzZGFsZTElMCMGA1UEChMcU3RhcmZpZWxkIFRlY2hub2xvZ2llcywgSW5jLjEzMDEGA1UECxMqaHR0cDovL2NlcnRzLnN0YXJmaWVsZHRlY2guY29tL3JlcG9zaXRvcnkvMTQwMgYDVQQDEytTdGFyZmllbGQgU2VjdXJlIENlcnRpZmljYXRlIEF1dGhvcml0eSAtIEcyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5ZBmS+z5RnGpIIO+6Wy/SslIaYF1Tm0k9ssXE/iwcVmEemsrhaQ0tRbly8zpQXAspC7W+jJ94ajelBCsMcHA2Gr/WSerdtb8C3RruKeuP8RU9LQxRN2TVoykTF6bicskg5viV3232BIfyYVt9NGA8VCbh67UCxAF+ye6KG0X6Q7WTbk5VQb/CiQFfi/GHXJs1IspjFd92tnrZhrTT6fff1LEMMWlyQ4CxVO/dzhoBiTDZsg3fjAeRXEjNf+Q2Cqdjeewkk08fyoKk9zNFkZl92CEi3ZLkSdzFJLg6u6PFuqNDj52F799iYCAREPnLeBDCXXaNuit24k69V0SjiMEgwIDAQABo4IBLDCCASgwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFCVFgWhQJjg9Oy0svs1q2bY9s2ZjMB8GA1UdIwQYMBaAFHwMMh+n2TB/xH1oo2Kooc6rB1snMDoGCCsGAQUFBwEBBC4wLDAqBggrBgEFBQcwAYYeaHR0cDovL29jc3Auc3RhcmZpZWxkdGVjaC5jb20vMDsGA1UdHwQ0MDIwMKAuoCyGKmh0dHA6Ly9jcmwuc3RhcmZpZWxkdGVjaC5jb20vc2Zyb290LWcyLmNybDBMBgNVHSAERTBDMEEGBFUdIAAwOTA3BggrBgEFBQcCARYraHR0cHM6Ly9jZXJ0cy5zdGFyZmllbGR0ZWNoLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQsFAAOCAQEAVmXK/vM/CqiTixjH3kNpEzQgvk5feKhrnNtqTUHbwRPs3DEAIl73AJ4M4DRlNPmxOk5IyBKBiFxbPghTevcaZN+4UGHMU1FAKUvC9K46X+TKrSbMTmFD5f1XpjdwzkMrsJTDkunhX6oQSbdp5ODQH2SkK80fb6D4hCQYznk9qZG/VBgTiZlUEQ1VxSYLeU9aHG75Y9sUgKQHq/qypbmI3ZH+ZTuko3m+iU3h0LD0yBcMCpYUfAm3bOHC2FXUGKCqQWlwJKO57+la3D7rlErwt95fDnb6+/tpA0VAUO5yDKQShoHNE9FOxDzKTg3SJvEAt7SmouFueoH9MKx6H8dZezCCBMMwggOroAMCAQICCQCthN4scmgY/DANBgkqhkiG9w0BAQsFADBoMQswCQYDVQQGEwJVUzElMCMGA1UEChMcU3RhcmZpZWxkIFRlY2hub2xvZ2llcywgSW5jLjEyMDAGA1UECxMpU3RhcmZpZWxkIENsYXNzIDIgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTYxMjEzMDcwMDAwWhcNMjExMjEzMDcwMDAwWjCBiDELMAkGA1UEBhMCVVMxEDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUxJTAjBgNVBAoTHFN0YXJmaWVsZCBUZWNobm9sb2dpZXMsIEluYy4xKzApBgNVBAMTIlN0YXJmaWVsZCBUaW1lc3RhbXAgQXV0aG9yaXR5IC0gRzEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDDErfsw30Hf/hAxEiB+MSDi8yZAoDhaslimDLFY72B+7wnZVNBABrtgJc2IiIym2hmC20BbTn/qIWoi5ensF9OBSJnVunPe+VKInvl5zBmDlckp1hyF7/6unxV+0YMIedLzjAg7ihwgqcdzK2FOYNJD9yfj7L/YxNjXNI5Dnh0Gna6VU6PBxglqM+1wixSHwnY41pKAy7uAdP/cnoTWgvmcKzsvXJ1BDYZxP/tFjCKFHTi5A/xKtuAE1QVVwXu0N6OP+4c2Fj6AAYoKx6QeqtbtSC6QfmXtit63Vs+Lfd5Psqgsm52VRSriWcud1UuDw7M34kR3yBGaNk2RgYCFX1/AgMBAAGjggFNMIIBSTAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIGwDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAdBgNVHQ4EFgQUxYZKIX7Z8rV9oQGsrF5d/hWC978wHwYDVR0jBBgwFoAUv1+30c7dH4b0W1Ws3NcQwg6piOcwOgYIKwYBBQUHAQEELjAsMCoGCCsGAQUFBzABhh5odHRwOi8vb2NzcC5zdGFyZmllbGR0ZWNoLmNvbS8wQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybC5zdGFyZmllbGR0ZWNoLmNvbS9yZXBvc2l0b3J5L3Nmcm9vdC5jcmwwUAYDVR0gBEkwRzBFBgtghkgBhv1uAQcXAjA2MDQGCCsGAQUFBwIBFihodHRwOi8vY3JsLnN0YXJmaWVsZHRlY2guY29tL3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEBCwUAA4IBAQAhbHjtY/cquM+DdpBHD70XnLkCj/dwBAEmkfJK9ZhTuYzOH4Mby5Mz8VyrUFHNb8Aw7vUlYDp1s6Z0uzvEZJv/6AKSoPwVc2P4kDLajq0vinNfSWRqHKwXcA3sso1s5YklpnflKnxuSZOqBE2fwtXchY/M0rAjhcPKS4xHW2bj6p0WxPJmItTIfXXmkj5le+Ra7iCfnOFniabcHEUzMHYt92C/vzTizopMQsTSeVXjfhQnP9I1U6cQJYTri46fZSCBdNiCfjnyUIihsqhBMxal1KFD8OZ5KJpDNPLDUedGEnWgb22Iy3lz/9sTyrLdES0v1hGebTse41C+h7sBmmfMMYICOzCCAjcCAQEwdTBoMQswCQYDVQQGEwJVUzElMCMGA1UEChMcU3RhcmZpZWxkIFRlY2hub2xvZ2llcywgSW5jLjEyMDAGA1UECxMpU3RhcmZpZWxkIENsYXNzIDIgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkCCQCthN4scmgY/DANBglghkgBZQMEAgEFAKCBmDAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTIwMDUzMDA4MTg0MlowKwYLKoZIhvcNAQkQAgwxHDAaMBgwFgQUWOfRd2Er0l4fusKAfLXHLuQExtMwLwYJKoZIhvcNAQkEMSIEIAptNaTioUKKtXKY5/NstJNdjRMGKXHBBA6pmakuTjyJMA0GCSqGSIb3DQEBAQUABIIBAB/Xsiv/HddeWE5l11jV05EbQbrghPUM6dpoTAuSeURtRVEanr2N28fa2Qzww8wtDOggI5gt5Bu8SjcPtorF505++g6VlIMcex4HEC9iSwoUu26BsPKijqJTwbxNgGc8siVE0KKZekpjODPzTX2ImNy+nZ59zhtDu1I4vXgB/yiakJJX1T7VCsoLZ7u5bA7QaR48+F+mXdYnYLMwWa+TNobbsmX68rl/nX89x7f5+OKIc/KbVlwsju5KqAld63ukNGMfYhGKejKGKXFuOpHuTEG0uvBxNghOLu9MZ4pOWdm37Pg1qLttfEbkdHWWUqwNHPcvNHLHhyk4d5DbZH112PoAAA==', 'base64');

    let totalReadData = '';
    await new Promise((resolve, reject) => {
      const reader = new AsymSecureFile.Reader({
        key: priKey
      });
      reader
        .on('header-complete', (next) => {
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
              next();
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
        })
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
      reader.write(payload);
      reader.end(null);
    });
    expect(totalReadData).to.equals('HELLO WORLD,I AM HAPPY');
  });

});
