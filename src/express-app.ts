import express, { Express } from "express";
import cors from "cors";
import cookieParser from "cookie-parser";

import { CORS_OPTION } from "./constants/cors-option";
import connectDB from "./db";
import { errorHandler } from "./middlewares/api-error-handling.middleware";
import authRouter from "./routes/auth.route";
import blogRoute from "./routes/blog.route";
import healthRouter from "./routes/health.route";
import userRouter from "./routes/user.route";

export const ExpressApp = async () => {
  const app: Express = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  app.use(cors(CORS_OPTION));
  app.use(cookieParser());

  app.use("/", healthRouter);
  app.use("/api/v1/auth", authRouter);
  app.use("/api/v1", userRouter);
  app.use("/api/v1/blog", blogRoute);
  connectDB();
  app.use(errorHandler);
  return app;
};
