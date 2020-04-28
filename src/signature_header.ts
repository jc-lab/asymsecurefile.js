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

import ReadBuffer from './read-buffer';

export default class SignatureHeader {
  static readonly SIGNATURE: number[] = [0x0a, 0x9b, 0xd8, 0x13, 0x97, 0x1f, 0x93, 0xe8, 0x6b, 0x7e, 0xdf, 0x05, 0x70, 0x54, 0x02];
  static readonly SIGNATURE_SIZE: number = SignatureHeader.SIGNATURE.length + 1;

  private _signature!: Buffer;
  private _version: number = 0; // uint8

  constructor() {
  }

  read(buffer: ReadBuffer): void {
    this._signature = buffer.readBuffer(SignatureHeader.SIGNATURE.length);
    this._version = buffer.readUInt8();
  }

  get signature(): Buffer {
    return this._signature;
  }

  get version(): number {
    return this._version;
  }
}
