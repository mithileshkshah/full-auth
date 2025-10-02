import { Request, Response } from "express";

import { STATUS_CODES } from "../constants/status-code";
import { Blog } from "../modals/Blog";
import { CustomRequest } from "../types/custom-request.type";
import { ApiResponse } from "../utils/ApiResponse";
import { asyncHandler } from "../utils/asyncHandler";


class BlogController {
  createBlog = asyncHandler(async (req: CustomRequest, res: Response) => {
    const { title, description, image } = req.body;
    const userId: string = req?.user?.id;

    const blogModal = new Blog({
      title,
      description,
      image,
      createdBy: userId,
    });
    await blogModal.save();
    res
      .status(STATUS_CODES.CREATED)
      .json(
        new ApiResponse(
          STATUS_CODES.CREATED,
          { blogModal },
          "Blog Created Successfully"
        )
      );
  });
  getAllBlogs = asyncHandler(async (req: Request, res: Response) => {
    const blogs = await Blog.find().populate("createdBy", "name email");
    res.status(STATUS_CODES.OK).json({ data: blogs });
  });
}

export default new BlogController();
