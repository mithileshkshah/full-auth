class ApiError extends Error {
  public readonly statusCode: number;
  public readonly success: boolean = false;

  constructor(
    statusCode: number,
    message = "Something went wrong",
    stack?: string
  ) {
    super(message);
    this.statusCode = statusCode;

    if (stack) {
      this.stack = stack;
    } else {
      Error.captureStackTrace(this, this.constructor);
    }
  }
}

export { ApiError };
