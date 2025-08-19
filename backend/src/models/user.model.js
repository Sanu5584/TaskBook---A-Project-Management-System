import mongoose, { Schema } from "mongoose"

const userSchema = new Schema(
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

export default User