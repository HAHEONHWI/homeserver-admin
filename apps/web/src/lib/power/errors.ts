export class PowerHttpError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "PowerHttpError";
    this.status = status;
  }
}
