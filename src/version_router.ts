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

import {
  Jasf4WriterDelegate
} from './internal/jasf4/writer-delegate';
import {
  Jasf4ReaderDelegate
} from './internal/jasf4/reader-delegate';
import {
  IExactWriterParams
} from './internal/intl';
import {
  IWriterHandlers, WriterDelegate
} from './internal/writer-delegate';
import {
  NotSupportedVersionError
} from './common';
import {
  IReaderHandlers, ReaderDelegate
} from './internal/reader-delegate';

export default class VersionRouter {
  public static createWriterDelegate(writerHandlers: IWriterHandlers, exactProps: IExactWriterParams): WriterDelegate {
    switch (exactProps.version) {
    case 4:
      return new Jasf4WriterDelegate(writerHandlers, exactProps);
    default:
      throw new NotSupportedVersionError();
    }
  }

  public static createReaderDelegate(readerHandlers: IReaderHandlers, version: number): ReaderDelegate {
    switch (version) {
    case 4:
      return new Jasf4ReaderDelegate(readerHandlers);
    default:
      throw new NotSupportedVersionError();
    }
  }

  public static getLatestWriterVersion(): number {
    return 4;
  }
}
