export default class ValidateFailedError extends Error {
  public readonly code: string;
  constructor(message?: string) {
    super(message);
    this.code = 'ValidateFailed';
  }
}
