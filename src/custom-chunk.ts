export enum CustomChunkFlags {
  ENCRYPT_WITH_AUTH_KEY = 1
}

export class CustomChunkBuilder {
  private _id: number = 0;
  private _flags: CustomChunkFlags = 0;
  private _data: Buffer | null = null;

  public id(value: number): this {
    this._id = value;
    return this;
  }

  public data(value: Buffer): this {
    this._data = value;
    return this;
  }

  public encryptWithAuthKey(value?: boolean): this {
    if (value || (typeof value === 'undefined')) {
      this._flags |= CustomChunkFlags.ENCRYPT_WITH_AUTH_KEY;
    } else {
      this._flags &= ~CustomChunkFlags.ENCRYPT_WITH_AUTH_KEY;
    }
    return this;
  }

  public build(): CustomChunk {
    if (!this._data) {
      throw new Error('data is empty');
    }
    return new CustomChunk(this._id, this._flags, this._data);
  }
}

export class CustomChunk {
  public readonly id: number;
  public readonly flags: number;
  public readonly data: Buffer;

  constructor (id: number, flags: number, data: Buffer) {
    this.id = id;
    this.flags = flags;
    this.data = data;
  }

  public hasFlag (flag: CustomChunkFlags): boolean {
    return !!(this.flags & flag);
  }

  public static builder (): CustomChunkBuilder {
    return new CustomChunkBuilder();
  }
}
