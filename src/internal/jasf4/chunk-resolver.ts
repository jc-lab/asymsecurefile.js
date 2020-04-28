import asn1js from 'asn1js';
import {
  Asn1ChunkFlags,
  Asn1EncryptedChunk,
  Asn1ObjectChunk,
  ChunkIds
} from './asn-objects';

type ChunkClass = any;

const CHUNK_MAP: Map<number, ChunkClass> = new Map();

export function addChunkType(chunkClass: ChunkClass) {
  CHUNK_MAP.set(chunkClass.CHUNK_ID, chunkClass);
}

export function parseChunk(seq: asn1js.Sequence): Asn1ObjectChunk {
  const id = (seq.valueBlock.value[0] as asn1js.Integer).valueBlock.valueDec;
  const flags = Asn1ChunkFlags.fromValue((seq.valueBlock.value[1] as asn1js.Integer).valueBlock.valueDec);
  const chunkType = (id < 0x80) ? CHUNK_MAP.get(id) : CHUNK_MAP.get(ChunkIds.CustomBegin);
  if (!chunkType) {
    throw new Error('Unknown Chunk Id');
  }
  if (flags.encryptWithAuthKey) {
    return Asn1EncryptedChunk.createWithReader(seq, chunkType);
  }
  return chunkType.decode(seq);
}
