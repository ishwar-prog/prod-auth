import userModel from "../models/user.model.js";
import crypt from "bcryptjs";
import jwt from "jsonwebtoken";

export async function register(req, res){
    const {username,email,password} = req.body;

    const isAlreadyRegistered = await userModel.findOne({
        $or:[
            {username},
            {email}
        ]
    })

    if(isAlreadyRegistered){
        res.status(400).json({
            message: "Username or email is already taken"
        })
        return;
    }

    const hashedPassword = crypto.createHash("ish123").update(password).digest("hex");

    const user = await userModel.create({
        username,
        email,
        password: hashedPassword
    })
}