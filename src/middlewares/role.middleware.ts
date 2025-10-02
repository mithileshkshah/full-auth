import { NextFunction, Response } from "express";

import { STATUS_CODES } from "../constants/status-code";
import { ApiError } from "../utils/ApiError";

const authorizeRole = (...allowedRoles: string[]) => {
  return (req: any, res: Response, next: NextFunction) => {
    if (!allowedRoles.includes(req.user.role)) {
      throw new ApiError(STATUS_CODES.NOT_AUTHORIZED, "Access denied");
    }
    next();
  };
};

export default authorizeRole;
