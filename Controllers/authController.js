import User from "../Models/userModel.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import nodemailer from "nodemailer";
import crypto from "crypto";
dotenv.config();

export const registerUser = async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const hashPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ name, email, password: hashPassword });
    await newUser.save();
    res
      .status(200)
      .json({ message: "User Registered Successfully", data: newUser });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

export const loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User Not Found" });
    }
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(400).json({ message: "Invalid Password" });
    }

    const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });
    user.token = token;
    await user.save();
    res
      .status(200)
      .json({ message: "User Logged In Successfully", token: token });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

export const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User Not Found" });
    }
    const resetToken = crypto.randomBytes(32).toString("hex");
    user.resetToken = resetToken;
    user.resetTokenExpiry = Date.now() + 3600000; 
    await user.save();
    const transporter = nodemailer.createTransport({
      service: "Gmail",
      auth: {
        user: process.env.PASS_MAIL,
        pass: process.env.PASS_KEY,
      },
    });
    const mailOptions = {
      from: process.env.PASS_MAIL,
      to: user.email,
      subject: "Password Reset Link",
      text: `You are receiving this because you have requested the reset of the password for your account 
      Please click the following link or paste it into your browser to complete the process
      https://graceful-capybara-c86bd7.netlify.app/reset-password/${user._id}/${resetToken}`,
    };
    transporter.sendMail(mailOptions, function (error) {
      if (error) {
        console.log(error);
        res
          .status(500)
          .json({ message: "Internal server error in sending the mail" });
      } else {
        res.status(200).json({ message: "Email Sent Successfully" });
      }
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

export const resetPassword = async (req, res) => {
    const { id, token } = req.params;
    const { password } = req.body;
  
    try {
      const user = await User.findById(id);
      if (!user || user.resetToken !== token || user.resetTokenExpiry < Date.now()) {
        return res.status(400).json({ message: "Invalid or expired token" });
      }
      const hash = await bcrypt.hash(password, 10);

      user.password = hash;
      user.resetToken = undefined;
      user.resetTokenExpiry = undefined;
      await user.save();
  
      res.status(200).json({ message: "Password reset successfully" });
    } catch (error) {
      res.status(500).json({ message: error.message });
    }
  };