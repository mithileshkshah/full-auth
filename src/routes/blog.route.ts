import express, { Router } from "express";
import verifyToken from "../middlewares/auth.middleware";
import authorizeRole from "../middlewares/role.middleware";
import UserController from "../controllers/UserController";
import BlogController from "../controllers/BlogController";

const blogRoute: Router = express.Router();

blogRoute.post(
  "/createBlog",
  verifyToken,
  authorizeRole("NORMAL"),
  BlogController.createBlog
);

blogRoute.get(
  "/getAllBlogs",
  verifyToken,
  authorizeRole("NORMAL"),
  BlogController.getAllBlogs
);

export default blogRoute;
