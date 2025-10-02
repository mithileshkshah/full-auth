import mongoose from "mongoose";
import { USER_ROLE } from "../constants/user-role";

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
    },
    username: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
    },
    password: {
      type: String,
      required: true,
    },
    role: {
      type: String,
      required: true,
      enum: USER_ROLE,
    },
    refreshToken: {
      type: String,
    },
  },
  {
    timestamps: true,
  }
);
export const User = mongoose.model("User", userSchema);
