import { z } from "zod";

export const registerSchema = z.object({
  name: z
    .string()
    .min(3, { message: "Name must be at least 3 characters long" })
    .trim(),
  email: z
    .email({ message: "Invalid email address" })
    .transform((val) => val.toLowerCase().trim()),
  password: z
    .string()
    .min(6, { message: "Password must be at least 6 characters long" }),
  username: z
    .string()
    .min(3, { message: "Username must be at least 3 characters long" })
    .transform((val) => val.toLowerCase().trim()),
  role: z.enum(["NORMAL", "ADMIN"]).default("NORMAL"),
});

export const loginSchema = z.object({
  email: z
    .email({ message: "Invalid email address" })
    .transform((val) => val.toLowerCase().trim()),
  password: z.string(),
});

export const resetPasswordSchema = z.object({
  resetToken: z.string(),
  password: z.string().min(6, "Password must be at least 6 characters"),
});

export const changePasswordSchema = z.object({
  currentPassword: z.string().min(6, "Password must be at least 6 characters"),
  newPassword: z.string().min(6, "Password must be at least 6 characters"),
});
