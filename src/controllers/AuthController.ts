import bcrypt from "bcrypt";
import { Request, Response } from "express";
import jwt, { JwtPayload } from "jsonwebtoken";

import { createHash, randomBytes } from "crypto";
import { COOKIE_OPTION } from "../constants/cookie-option";
import { STATUS_CODES } from "../constants/status-code";
import { User } from "../modals/User";
import { forgotPasswordMail } from "../templates/forgot-password";
import { CustomRequest } from "../types/custom-request.type";
import { ApiError } from "../utils/ApiError";
import { ApiResponse } from "../utils/ApiResponse";
import { asyncHandler } from "../utils/asyncHandler";
import { sendMail } from "../utils/mailService";

class AuthController {
  createUser = asyncHandler(async (req: Request, res: Response) => {
    const { name, email, username, password, role } = req.body;

    const user = await User.findOne({ email });
    if (user) {
      throw new ApiError(
        STATUS_CODES.CONFLICT,
        "User already exist in the system. Please try login"
      );
    }

    const hashedPassword: string = await bcrypt.hash(password, 10);
    const userModal = new User({
      name,
      email,
      username,
      password: hashedPassword,
      role,
    });
    await userModal.save();
    res
      .status(STATUS_CODES.CREATED)
      .json(
        new ApiResponse(
          STATUS_CODES.CREATED,
          { userModal },
          "User Created Successfully"
        )
      );
  });

  login = asyncHandler(async (req: Request, res: Response) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      throw new ApiError(404, "User does not exist");
    } else {
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        throw new ApiError(400, "Invalid credential");
      } else {
        const accessTokenSecret = process.env.ACCESS_TOKEN_SECRET as string;
        const refreshTokenSecret = process.env.REFRESH_TOKEN_SECRET as string;
        const accessToken = jwt.sign(
          { id: user._id, role: user.role },
          accessTokenSecret,
          {
            expiresIn: "1m",
          }
        );
        const refreshToken = jwt.sign({ id: user._id }, refreshTokenSecret, {
          expiresIn: "1d",
        });

        user.refreshToken = refreshToken;
        await user.save();

        res
          .status(STATUS_CODES.OK)
          .cookie("accessToken", accessToken, COOKIE_OPTION)
          .cookie("refreshToken", refreshToken, COOKIE_OPTION)
          .json(
            new ApiResponse(
              200,
              {
                name: user.name,
                username: user.username,
                email: user.email,
                role: user.role,
                accessToken,
              },
              "User logged In Successfully"
            )
          );
      }
    }
  });

  logout = asyncHandler(async (req: CustomRequest, res: Response) => {
    await User.findByIdAndUpdate(
      req?.user?.id,
      {
        $unset: {
          refreshToken: 1, // this removes the field from document
        },
      },
      {
        new: true,
      }
    );
    res
      .clearCookie("accessToken")
      .clearCookie("refreshToken")
      .status(200)
      .json(new ApiResponse(200, {}, "User logged out Successfully"));
  });

  refreshAccessToken = asyncHandler(async (req: Request, res: Response) => {
    const incomingRefreshToken = req.cookies.refreshToken;

    if (!incomingRefreshToken) {
      throw new ApiError(
        STATUS_CODES.NOT_AUTHENTICATED,
        "unauthorized request"
      );
    }

    const secret = process.env.REFRESH_TOKEN_SECRET as string;

    const decodedToken = jwt.verify(incomingRefreshToken, secret) as JwtPayload;

    const user = await User.findById(decodedToken?.id);

    if (!user) {
      throw new ApiError(
        STATUS_CODES.NOT_AUTHENTICATED,
        "Invalid refresh token"
      );
    }

    if (incomingRefreshToken !== user?.refreshToken) {
      throw new ApiError(401, "Refresh token is expired or used");
    }

    const accessTokenSecret = process.env.ACCESS_TOKEN_SECRET as string;
    const refreshTokenSecret = process.env.REFRESH_TOKEN_SECRET as string;
    const accessToken = jwt.sign(
      { id: user._id, role: user.role },
      accessTokenSecret,
      {
        expiresIn: "1m",
      }
    );
    const newRefreshToken = jwt.sign({ id: user._id }, refreshTokenSecret, {
      expiresIn: "1d",
    });

    // Save new refresh token in DB
    user.refreshToken = newRefreshToken;
    await user.save();

    return res
      .status(200)
      .cookie("accessToken", accessToken, COOKIE_OPTION)
      .cookie("refreshToken", newRefreshToken, COOKIE_OPTION)
      .json(
        new ApiResponse(
          200,
          { accessToken, refreshToken: newRefreshToken },
          "Access token refreshed"
        )
      );
  });

  forgotPassword = asyncHandler(async (req: Request, res: Response) => {
    const { email } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
      throw new ApiError(404, "User does not exist");
    }

    // Generate reset token
    const resetToken = randomBytes(32).toString("hex");
    const resetTokenExpiry = Date.now() + 15 * 60 * 1000; // 15 mins

    // Save hashed token in DB
    user.resetPasswordToken = createHash("sha256")
      .update(resetToken)
      .digest("hex");
    user.resetPasswordExpire = new Date(resetTokenExpiry); // ✔ correct type
    await user.save();

    // Create reset link
    const resetUrl = `${process.env.CLIENT_URL}/reset-password/${resetToken}`;

    await sendMail(
      user.email,
      "Password Reset Request",
      forgotPasswordMail(resetUrl, user.username)
    );

    return res
      .status(200)
      .json(new ApiResponse(200, {}, "Password reset email sent"));
  });

  authenticate = asyncHandler(async (req: CustomRequest, res: Response) => {
    res.json({ message: "This is a protected route", user: req.user });
  });
}

export default new AuthController();
