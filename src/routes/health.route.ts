import express, { Router } from "express";
import HealthController from "../controllers/HealthController";
const healthRouter: Router = express.Router();

healthRouter.get("/", HealthController.healthCheck);

export default healthRouter;
