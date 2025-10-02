import { Request, Response } from "express";

import { STATUS_CODES } from "../constants/status-code";
import { asyncHandler } from "../utils/asyncHandler";
import { User } from "../modals/User";

class UserController {
  getAllUsers = asyncHandler(async (_: Request, res: Response) => {
    const users = await User.find();
    res.status(STATUS_CODES.OK).json({ data: users });
  });
}

export default new UserController();
