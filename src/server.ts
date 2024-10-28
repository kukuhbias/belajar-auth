import express from "express";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import mongoose from "mongoose";
import { User } from "./models/user.schema";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import { Auth } from "./models/auth.schema";

dotenv.config();

console.log(process.env.MONGO_URI);

mongoose
  .connect(process.env.MONGO_URI as string, {
    serverSelectionTimeoutMS: 60000, // Increase timeout
  })
  .then(() => console.log("mongodb connection success"))
  .catch((error) => console.log(error));

const app = express();
app.use(express.json());
app.use(cookieParser());

app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;
  console.time("Hashed");
  const hashedPassword = await bcrypt.hash(password, 10);
  console.timeEnd("Hashed");

  // payload /data yg akan di transfer
  const newUser = {
    name,
    email,
    password: hashedPassword,
  };

  const createUser = new User(newUser);
  const data = await createUser.save();

  return res.json({ message: "user register success", data });
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || password.length < 4) {
    return res.json({
      message:
        "Email should be valid and password should have minimum 8 characters",
    });
  }
  const user = await User.findOne({ email });
  if (!user) {
    return res
      .status(403)
      .json({ message: "Invalid credentials :user not found" });
  }

  const isPasswordMatch = await bcrypt.compare(
    password,
    user.password as string
  );
  if (!isPasswordMatch) {
    return res
      .status(403)
      .json({ message: "Invalid credentials :invalid password" });
  }
  //auth strategy JWS/SESSION
  const payload = {
    id: user.id,
    name: user.name,
    email: user.email,
  };

  const accesToken = jwt.sign(payload, process.env.JWT_ACCESS_SECRET!, {
    expiresIn: 300,
  });

  const refreshToken = jwt.sign(payload, process.env.JWT_REFRESH_SECRET!, {
    expiresIn: "7d",
  });

  const newRefreshToken = new Auth({
    userId: user.id,
    refreshToken,
  });
  newRefreshToken.save();

  return res
    .cookie("accessToken", accesToken, { httpOnly: true })
    .cookie("refreshToken", refreshToken, { httpOnly: true })
    .status(200)
    .json({ message: "login success !" });
});

app.post("/logout", async (req, res) => {
  const { refreshToken } = req.cookies;

  await Auth.findOneAndDelete({ refreshToken });
  return res
    .clearCookie("accessToken")
    .clearCookie("refreshToken")
    .status(200)
    .json({ message: "sudah berhasil keluar" });
});

//RESOURCE ENDPOINT
app.get("/resources", async (req, res) => {
  const { accessToken, refreshToken } = req.cookies;
  //check accessToken refreshToken
  if (!accessToken && !refreshToken) {
    console.log("accessToken & refreshToken invalid");
    return res
      .status(401)
      .json({ message: "Unauthorized, please login first !" });
  }
  if (accessToken) {
    try {
      jwt.verify(accessToken, process.env.JWT_ACCESS_SECRET as string);
      console.log("access token valid");
      return res.status(200).json({ message: "Ini datanya" });
    } catch (error) {
      try {
        console.log("verification proccess refresh token");
        jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET as string);
        console.log("check refreshToken on DB");
        const activeRefreshToken = await Auth.findOne({
          refreshToken: refreshToken,
        });

        if (!activeRefreshToken) {
          console.log("Refresh token not found on DB");
          return res.status(401).json({ message: "please re-login" });
        }
        const payload = jwt.decode(refreshToken) as {
          id: string;
          name: string;
          email: string;
        };

        console.log("create new Access token");
        const newAccessToken = jwt.sign(
          {
            id: payload?.id,
            name: payload.name,
            email: payload.email,
          },
          process.env.JWT_ACCESS_SECRET as string,
          { expiresIn: 300 }
        );

        return res
          .cookie("accessToken", newAccessToken, { httpOnly: true })
          .json({ message: "ini datanya" });
      } catch (error) {
        console.log(error);
      }
    }
  }
});

app.listen(process.env.PORT, () => {
  console.log(`process running at port: ${process.env.PORT}`);
});
