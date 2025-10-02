import { Request, Response } from "express";

class HealthController {
  healthCheck = (req: Request, res: Response) => {
    res.send("Application is running fine...");
  };
}

export default new HealthController();
