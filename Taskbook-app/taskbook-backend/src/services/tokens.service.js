import bcrypt from "bcryptjs";
import crypto from "node:crypto"
import jwt from "jsonwebtoken"

const hashPassword = (password) => {
    const salt = 10
    return bcrypt.hash(password, salt)
}

const isPasswordMatch = (password, hashedPassword) => {
    return bcrypt.compare(password, hashedPassword)
}

const generateAccessToken = (user) => {
    return jwt.sign(
        {
            _id: user._id,
        },
        process.env.ACCESS_TOKEN_SECRET,
        {
            expiresIn: process.env.ACCESS_TOKEN_EXPIRY
        }
    )
}

const generateRefreshToken = (user) => {
    return jwt.sign(
        {
            _id: user._id
        },
        process.env.REFRESH_TOKEN_SECRET,
        {
            expiresIn: process.env.REFRESH_TOKEN_EXPIRY
        }
    )
}

const hashToken = (token) => {
    return crypto.createHash("sha256").update(token).digest("hex")
}

const generateToken = () => {

    const unHashedToken = crypto.randomBytes(32).toString("hex")
    const hashedToken = crypto.createHash("sha256").update(unHashedToken).digest("hex")
    const tokenExpiry = Date.now() + (10 * 60 * 1000)

    return { unHashedToken, hashedToken, tokenExpiry }
}

export { hashPassword, isPasswordMatch, generateAccessToken, generateRefreshToken, generateToken, hashToken }