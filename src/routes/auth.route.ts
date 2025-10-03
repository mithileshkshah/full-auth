import express, { Router } from "express";
import AuthController from "../controllers/AuthController";
import verifyToken from "../middlewares/auth.middleware";
import { validate } from "../middlewares/validateRequest";
import { resetPasswordSchema } from "../validators/authValidator";

const authRouter: Router = express.Router();

authRouter.post("/createUser", AuthController.createUser);
authRouter.post("/login", AuthController.login);
authRouter.post("/refresh-token", AuthController.refreshAccessToken);
authRouter.get("/logout", verifyToken, AuthController.logout);
authRouter.post("/forgot-password", AuthController.forgotPassword);
authRouter.post(
  "/reset-password",
  validate(resetPasswordSchema),
  AuthController.resetPassword
);
authRouter.get("/authenticate", verifyToken, AuthController.authenticate);

export default authRouter;
