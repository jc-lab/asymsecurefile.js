import {
  CustomChunk 
} from '../custom-chunk';

export interface WriterDelegate {
  init(): Promise<void>;
  addCustomChunk(chunk: CustomChunk): Promise<void>;
  write(chunk: Buffer, callback: (err: any) => void);
  final(callback: (err: any) => void);
}

export interface IWriterHandlers {
  push(chunk: Buffer): Promise<boolean>;
  emitError(e: any): void;
}
