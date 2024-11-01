import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import connectDb from "./Database/dbConfig.js";
import authRoute from "./Routers/authRouter.js"

dotenv.config();

const app = express();

app.use(cors());
app.use(express.json());

connectDb();

app.get("/",(req,res)=>{
  res.status(200).send("Welcome to our api")
})

app.use("/api/auth",authRoute)

const port = process.env.PORT || 5000;

app.listen(port,()=>{
    console.log("server started");
    
})