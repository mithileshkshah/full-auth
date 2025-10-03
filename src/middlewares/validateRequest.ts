import { NextFunction, Request, Response } from "express";
import { ZodType } from "zod";

export const validate =
  (schema: ZodType<unknown>) =>
  (req: Request, res: Response, next: NextFunction) => {
    const result = schema.safeParse(req.body);

    if (result.error) {
      const zodError = result.error;
      const errors = zodError.issues.map((issue) => ({
        field: issue.path.join("."),
        message: issue.message,
      }));

      return res.status(400).json({
        success: false,
        message: "Validation error",
        errors,
      });
    }

    req.body = result.data;
    next();
  };
