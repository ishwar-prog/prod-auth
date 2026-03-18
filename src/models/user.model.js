import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: [true, "Username is required"],
    unique: [true, "Username is already taken"],
  },
  email: {
    type: String,
    required: [true, "Email is required"],
    unique: [true, "Email is already taken"],
  },
  password: {
    type: String,
    required: [true, "Password is required"],
  },
});

const userModel = mongoose.model("User", userSchema);

export default userModel;
