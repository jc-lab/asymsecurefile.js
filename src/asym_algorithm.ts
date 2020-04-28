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

import * as crypto from 'crypto';

export default class AsymAlgorithm {
  static readonly Unknown = new AsymAlgorithm(0, undefined, 'Unknown', 'Unknown');
  static readonly EC = new AsymAlgorithm(0x11, [0x06, 0x04, 0x2B, 0x81, 0x04, 0x00], 'EC', 'NONEwithECDSA');
  static readonly PRIME = new AsymAlgorithm(0x11, [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01], 'EC', 'NONEwithECDSA');
  static readonly RSA = new AsymAlgorithm(0x11, [0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01], 'EC', 'NONEwithECDSA');

  private _keyType: number;
  private _identifier: any;
  private _algorithm: string;
  private _signatureAlgorithm: string;

  constructor(keyType: number, identifier: any, algorithm: string, signatureAlgorithm: string) {
    this._keyType = keyType;
    this._identifier = identifier;
    this._algorithm = algorithm;
    this._signatureAlgorithm = signatureAlgorithm;
  }

  get keyType(): number {
    return this._keyType;
  }

  get identifier(): any {
    return this._identifier;
  }

  get algorithm(): string {
    return this._algorithm;
  }

  get signatureAlgorithm(): string {
    return this._signatureAlgorithm;
  }
}
