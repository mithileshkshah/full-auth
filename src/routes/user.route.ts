import express, { Router } from "express";
import verifyToken from "../middlewares/auth.middleware";
import authorizeRole from "../middlewares/role.middleware";
import UserController from "../controllers/UserController";

const userRouter: Router = express.Router();

userRouter.get(
  "/getAllUsers",
  verifyToken,
  authorizeRole("ADMIN"),
  UserController.getAllUsers
);

export default userRouter;
