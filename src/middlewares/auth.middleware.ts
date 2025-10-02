import { NextFunction, Response, Request } from "express";
import jwt, { Jwt, JwtPayload } from "jsonwebtoken";
import { ApiError } from "../utils/ApiError";
import { asyncHandler } from "../utils/asyncHandler";
import { CustomRequest } from "../types/custom-request.type";

const verifyToken = asyncHandler(
  async (req: CustomRequest, res: Response, next: NextFunction) => {
    try {
      const token = req.cookies?.accessToken;

      if (!token) {
        throw new ApiError(401, "Unauthorized request");
      }
      const secret = process.env.ACCESS_TOKEN_SECRET as string;

      const decodedToken = jwt.verify(token, secret);

      req.user = decodedToken as JwtPayload;
      next();
    } catch (error) {
      throw new ApiError(401, "Invalid access token");
    }
  }
);

export default verifyToken;
