import userModel from "../models/user.model.js";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import config from "../config/config.js";

export async function register(req, res) {
  const { username, email, password } = req.body;

  const isAlreadyRegistered = await userModel.findOne({
    $or: [{ username }, { email }],
  });

  if (isAlreadyRegistered) {
    res.status(400).json({
      message: "Username or email is already taken",
    });
    return;
  }

  const hashedPassword = crypto
    .createHash("sha256")
    .update(password)
    .digest("hex");

  const user = await userModel.create({
    username,
    email,
    password: hashedPassword,
  });

  const accessToken = jwt.sign(
    {
      id: user._id,
    },
    config.JWT_SECRET,
    {
      expiresIn: "15m",
    },
  );

  const refreshToken = jwt.sign(
    {
      id: user._id,
    },
    config.JWT_SECRET,
    {
      expiresIn: "7d",
    },
  );

  res.cookie("refreshtoken", refreshToken, {
    httpOnly: true,
    secure:true,
    sameSite: "strict", 
    maxAge: 7 * 24 * 60 * 60 * 1000,
  })

  res.status(201).json({
    message: "User registered successfully",
    user: {
      username: user.username,
      email: user.email,
    },
    accessToken,
    refreshToken,
  });
}

export async function getMe(req, res) {
  const accessToken = req.headers.authorization?.split(" ")[1];

  if (!accessToken) {
    return res.status(401).json({
      message: "Access token not found",
    });
  }

  const decoded = jwt.verify(accessToken, config.JWT_SECRET);

  const user = await userModel.findById(decoded.id);

  res.status(200).json({
    message: "User fetched successfully",
    user: {
      username: user.username,
      email: user.email,
    },
  });
}

export async function refreshToken(req,res){
    const refreshToken = req.cookies.refreshtoken;

    if(!refreshToken){
        return res.status(401).json({
            message:"Refresh token not found"
        })
    }

    const decoded = jwt.verify(refreshToken, config.JWT_SECRET);

    const accessToken = jwt.sign(
        {
            id:decoded.id
        },
        config.JWT_SECRET,
        {
            expiresIn:"15m"
        }
    )

    const newRefreshToken = jwt.sign({
        id:decoded.id
    },config.JWT_SECRET,{
        expiresIn:"7d"
    }
)

res.cookie("refreshtoken", newRefreshToken, {
    httpOnly: true,
    secure:true,
    sameSite: "strict", 
    maxAge: 7 * 24 * 60 * 60 * 1000,
  })
    res.status(200).json({
        message:"Access Token refreshed successfully",
        accessToken
    })
}
