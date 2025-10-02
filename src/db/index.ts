import mongoose from "mongoose";

const connectDB = async (): Promise<void> => {
  const mongo_url: string = process.env.MONDO_DB_URL as string;
  mongoose
    .connect(mongo_url, {
      dbName: "blog",
    })
    .then(() => {
      console.log("Database connected...");
    })
    .catch((error) => {
      console.log(error);
    });
};

export default connectDB;
