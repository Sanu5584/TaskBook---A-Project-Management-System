import { ApiError } from "../utils/api-error.utils.js"
import { ApiResponse } from "../utils/api-response.utils.js"
import { asyncHandler } from "../utils/async-handler.utils.js"
import { User } from "../models/user.model.js"
import { sendMail, emailVerificationMailgenContent } from "../services/mailing.service.js"
import { uploadOnCloudinary } from "../services/cloudinary.service.js"

import crypto from "node:crypto"

const register = asyncHandler(async (req, res) => {

    // - get data from the body
    const { fullname, username, email, password } = req.body

    // - validate the data we get from the user
    if (!fullname && !username && !email && !password) {
        throw new ApiError(404, "Invalid Credentials")
    }

    // - check if user already exists or not
    const existedUser = await User.findOne({
        $or: [{ email }, { username }]
    })

    if (existedUser) {
        throw new ApiError(400, "User already exists")
    }

    // create new user
    const newUser = await User.create({
        email,
        fullname,
        username,
        password,
    })

    // - generate a verification token
    const { hashedToken, unHashedToken, tokenExpiry } = newUser.generateToken()

    newUser.emailVerificationToken = hashedToken
    newUser.emailVerificationExpiry = tokenExpiry
    newUser.isEmailVerified = false

    // - upload avatar file to cloudinary
    console.log(req.file);
    let avatarUrl;
    const avatarPath = req.file?.avatar

    if (avatarPath) avatarUrl = await uploadOnCloudinary(avatarPath)

    if (avatarPath && avatarUrl) {
        newUser.avatar({
            url: avatarUrl,
            path: avatarPath
        })
    }

    // - save the verfication token in db
    await newUser.save({ validateBeforeSave: false })

    // - sent verification token to user via email 
    const verifyEmailContent = emailVerificationMailgenContent
        (
            newUser.fullname,
            `${req.protocol}/${req.get("host")}/api/v1/auth/verify-email/${unHashedToken}`
        )

    await sendMail(newUser?.email, "Verify Email", verifyEmailContent)

    // - send success status to user
    const createdUser = await User.findById(newUser._id, "-password -emailVerificationExpiry -emailVerificationToken -refreshToken -forgotPasswordToken -forgotPasswordTokenExpiry")

    if (!createdUser) {
        throw new ApiError(500, "Something went wrong while registering the user")
    }

    res.status(401).json(
        new ApiResponse(401, "User registered successfully", { newUser: createdUser })
    )

})

const resendEmailVerification = asyncHandler(async (req, res) => {
    // get the user from the body
    const { email } = req.body

    // validate the user
    if (!email) {
        throw new ApiError(404, "Email is required")
    }

    //find user based on email
    const newUser = await User.findOne({ email: email })

    if (!newUser) {
        throw new ApiError(404, "User not found")
    }

    // check if user is already verified
    if (newUser.isEmailVerified == true) {
        throw new ApiError(400, "User already verified")
    }

    // generate the tokens
    const { hashedToken, unHashedToken, tokenExpiry } = newUser.generateToken()

    newUser.emailVerificationToken = hashedToken
    newUser.emailVerificationExpiry = tokenExpiry

    await newUser.save({ validateBeforeSave: false })

    // send the new verification email to user
    const verificationUrl = `${req.protocol}/${req.get({ host })}/api/v1/auth/verify-email/${unHashedToken}`
    const verificationMailContent = emailVerificationMailgenContent(newUser.fullname, verificationUrl)

    await sendMail(newUser?.email, "Verify Email", verificationMailContent)

    // save the user and send success response

    const createdUser = await User.findById(newUser._id, "-password -emailVerificationExpiry -emailVerificationToken -refreshToken -forgotPasswordToken -forgotPasswordTokenExpiry")

    res
        .status(201)
        .json(
            new ApiResponse(201, "Verification mail sent successfully", createdUser)
        )
})

const verifyUser = asyncHandler(async (req, res) => {
    // get the verificationToken from the params
    const { verificationToken } = req.params

    // validate the verificationToken
    if (!verificationToken) {
        throw new ApiError(404, "VerificationToken is required")
    }


    // hash the verificationToken and compare it with the field emailVerificationToken

    const hashedToken = crypto.createHash("sha256").update(verificationToken).digest("hex")

    // find user on basis of the verification token and verificationTokenExpiry
    const newUser = await User.findOne({
        emailVerificationToken: hashedToken,
        emailVerificationExpiry: { $gt: new Date() }
    })

    if (!newUser) {
        throw new ApiError(404, "User not found")
    }

    // if validated then set the isEmailVerified to true in db
    newUser.isEmailVerified = true

    // remove the verification from db
    newUser.emailVerificationToken = undefined
    newUser.emailVerificationExpiry = undefined

    // assign access and refresh token to the users
    const accessToken = newUser.generateAccessToken()
    const refreshToken = newUser.generateRefreshToken()

    if (!refreshToken || !accessToken) {
        throw new ApiError(500, "Internal Server Error: while assigning the JWT tokens")
    }

    // send the access token to user via cookies
    const cookieOptions = {
        httpOnly: true,
        secure: true,
        sameSite: "none",
        maxAge: 24 * 60 * 60 * 1000
    }

    res.cookie("accessToken", accessToken, cookieOptions)
    res.cookie("refreshToken", refreshToken, cookieOptions)

    // store the hashed refresh token in db
    const hashedRefreshToken = crypto.createHash("sha256").update(refreshToken).digest("hex")

    newUser.refreshToken = hashedRefreshToken

    // save the user and send success response
    await newUser.save({ validateBeforeSave: false })

    const verifiedUser = await User.findById(newUser._id, "-password -emailVerificationExpiry -emailVerificationToken -refreshToken -forgotPasswordToken -forgotPasswordTokenExpiry")

    res
        .status(202)
        .json(
            new ApiResponse(202, "User verified successfully", verifiedUser)
        )
})

const login = asyncHandler(async (req, res) => {
    // get data from the body
    const { email, username, password } = req.body

    // validate the data
    if (!(email || username) && !password) {
        throw new ApiError(400, "login credentials is required")
    }

    // check the already logged in user
    const user = await User.findOne({
        $or: [{ email }, { username }]
    })

    if (!user) {
        throw new ApiError(404, "User not found")
    }

    // check the verification of user
    const isEmailVerified = await user.isEmailVerified

    if (!isEmailVerified) {
        throw new ApiError(400, "User is not verified")
    }

    // check the password of the user
    const matchPassword = await user.isPasswordMatch(password)

    if (!matchPassword) {
        throw new ApiError(400, "Password not matched, please enter the valid password")
    }

    // assign access and refresh token to the user
    const refreshToken = await user.generateRefreshToken()
    const accessToken = await user.generateAccessToken()

    if (!refreshToken || !accessToken) {
        throw new ApiError(500, "Internal Server Error: while assigning the JWT tokens")
    }

    // send the access token to user via cookies
    const cookieOptions = {
        httpOnly: true,
        secure: true,
        maxAge: 24 * 60 * 60 * 1000
    }

    res.cookie("accessToken", accessToken, cookieOptions)
    res.cookie("refreshToken", refreshToken, cookieOptions)

    // store the hashed refresh token in db
    const hashedRefreshToken = crypto.createHash("sha256").update(refreshToken).digest("hex")

    user.refreshToken = hashedRefreshToken
    await user.save({ validateBeforeSave: false })

    // send success response to the user
    const loggedInUser = await User.findById(newUser._id, "-password -emailVerificationExpiry -emailVerificationToken -refreshToken -forgotPasswordToken -forgotPasswordTokenExpiry")

    res
        .status(201)
        .json(
            new ApiResponse(201, "User logged in successfully", loggedInUser)
        )
})

const logout = asyncHandler(async (req, res) => {
    // get the data from the req object
    const { _id } = req.user

    // find the user based on _id
    const user = await User.findByIdAndUpdate(_id, {
        refreshToken: undefined
    })

    if (!user) {
        throw new ApiError(401, "Unauthorised request")
    }

    // clear the cookie from res object
    const cookieOptions = {
        httpOnly: true,
        secure: true,
        sameSite: "none",
        maxAge: 24 * 60 * 60 * 1000
    }

    res.clearCookie("accessToken", cookieOptions)
    res.clearCookie("refreshToken", cookieOptions)

    // send success response to the user
    res
        .status(200)
        .json(
            new ApiResponse(202, "Logged out successfully", null)
        )

})

const getUser = asyncHandler(async (req, res) => {
    // get data from the req
    const { _id } = req.user

    // find the user based on id
    const user = await User.findOne({ _id }).select("-password -emailVerificationExpiry -emailVerificationToken -refreshToken -forgotPasswordToken -forgotPasswordTokenExpiry")

    if (!user) {
        throw new ApiError(404, "User not found")
    }

    // send the success response to user
    res
        .status(200)
        .json(
            new ApiResponse(200, "Fetched the user data successfully", user)
        )
})

export { register, verifyUser, resendEmailVerification, login, logout, getUser }