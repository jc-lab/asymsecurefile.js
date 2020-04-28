import * as asn1js from 'asn1js';

const isArrayBufferSupported = (Buffer.from(new Uint8Array([1]).buffer)[0] === 1);

export const arrayBufferToBuffer = isArrayBufferSupported ? arrayBufferToBufferAsArgument : arrayBufferToBufferCycle;

function arrayBufferToBufferAsArgument(ab): Buffer {
  return Buffer.from(ab);
}

function arrayBufferToBufferCycle(ab): Buffer {
  var buffer = Buffer.alloc(ab.byteLength);
  var view = new Uint8Array(ab);
  for (var i = 0; i < buffer.length; ++i) {
    buffer[i] = view[i];
  }
  return buffer;
}

export function bufferClone(value: ArrayBuffer): ArrayBuffer {
  return value.slice(0, value.byteLength);
}

export function bufferToArrayBuffer(buffer: Buffer | ArrayBuffer): ArrayBuffer {
  if (buffer instanceof ArrayBuffer)
    return buffer;
  var ab = new ArrayBuffer(buffer.length);
  var view = new Uint8Array(ab);
  for (var i = 0; i < buffer.length; ++i) {
    view[i] = buffer[i];
  }
  return ab;
}

export function asnObjectToInteger(value: asn1js.LocalValueBlock): number {
  return (value as asn1js.Integer).valueBlock.valueDec;
}

export function copyToAsn1Integer(value: asn1js.LocalValueBlock): asn1js.Integer {
  return new asn1js.Integer({
    value: (value as asn1js.Integer).valueBlock.valueDec
  });
}

export function copyToAsn1OctetString(value: asn1js.LocalValueBlock): asn1js.OctetString {
  return new asn1js.OctetString({
    valueHex: bufferClone((value as asn1js.OctetString).valueBlock.valueHex)
  });
}

export function copyToAsn1ObjectIdentifier(value: asn1js.LocalValueBlock): asn1js.ObjectIdentifier {
  return (value as asn1js.ObjectIdentifier);
}
