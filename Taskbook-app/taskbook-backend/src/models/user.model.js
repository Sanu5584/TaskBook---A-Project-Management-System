import bcrypt from "bcryptjs"
import jwt from "jsonwebtoken"
import crypto from "node:crypto"

import mongoose, { Schema } from "mongoose"

export const userSchema = new Schema(
    {
        avatar: {
            type: {
                url: String,
                path: String
            },
            default: {
                url: `https://via.placeholder.com/200x200.png`,
                path: ""
            }
        },
        username: {
            type: String,
            required: true,
            trim: true,
            lowercase: true,
            index: true,
            unique: true
        },
        email: {
            type: String,
            required: true,
            unique: true,
            trim: true,
            lowercase: true
        },
        fullname: {
            type: String,
            required: true,
            trim: true
        },
        password: {
            type: String,
            required: true,
            trim: true
        },
        isEmailVerified: {
            type: Boolean,
            default: false,
        },
        refreshToken: {
            type: String
        },
        forgotPasswordToken: {
            type: String
        },
        forgotPasswordTokenExpiry: {
            type: Date
        },
        emailVerificationToken: {
            type: String,
        },
        emailVerificationExpiry: {
            type: Date,
        },
    },
    {
        timestamps: true
    }
)

const User = mongoose.model("User", userSchema)

userSchema.pre("save", async function (next) {
    if (!this.isModified("password")) return next();
    this.password = await bcrypt.hash(this.password, 10);
    next();
})

userSchema.methods.isPasswordMatch = async function(password){
    return await bcrypt.compare(password, this.password)
}

userSchema.methods.generateAccessToken = function(){
    return jwt.sign(
        {
            _id: this._id,
            email: this.email,
            username: this.username
        },
        process.env.ACCESS_TOKEN_SECRET,
        {
            expiresIn: ACCESS_TOKEN_EXPIRY
        }
    )
}

userSchema.methods.generateRefreshToken = function(){
    return jwt.sign(
        {
            _id: this._id,
            email: this._email,
            username: this.username
        },
        process.env.REFRESH_TOKEN_SECRET,
        {
            expiresIn: REFRESH_TOKEN_EXPIRY
        }
    )
}

userSchema.generateToken = function(){
    const unHashedToken = crypto.randomBytes(32).toString("hex")

    const hashedToken = crypto.createHash("sha256").update(unHashedToken).digest("hex")

    const tokenExpiry = Date.now() + (10 * 60 * 1000)

    return {unHashedToken, hashedToken, tokenExpiry}
}

export default User