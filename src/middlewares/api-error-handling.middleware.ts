import { Request, Response, NextFunction, ErrorRequestHandler } from "express";
import { ApiError } from "../utils/ApiError";

// Error handling middleware
const errorHandler: ErrorRequestHandler = async (
  err: Error,
  _: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  if (err instanceof ApiError) {
    res.status(err.statusCode).json({
      success: false,
      message: err.message,
    });
  } else {
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
  next();
};

export { errorHandler };
