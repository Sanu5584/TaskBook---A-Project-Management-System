import jwt from "jsonwebtoken"

import { ApiError } from "../utils/api-error.utils.js"
import { ApiResponse } from "../utils/api-response.utils.js"
import { asyncHandler } from "../utils/async-handler.utils.js"
import User from "../models/user.model.js"
import { sendMail, emailVerificationMailgenContent, forgotPasswordRequestMailGenContent } from "../services/mailing.service.js"
import { uploadOnCloudinary } from "../services/cloudinary.service.js"
import { hashPassword, generateAccessToken, generateRefreshToken, isPasswordMatch, generateToken, hashToken } from "../services/tokens.service.js"

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

    // hash the password
    const hashedPassword = await hashPassword(password)

    // create new user
    const newUser = await User.create({
        email,
        fullname,
        username,
        password: hashedPassword,
    })

    // - generate a verification token
    const { hashedToken, unHashedToken, tokenExpiry } = generateToken()

    newUser.emailVerificationToken = hashedToken
    newUser.emailVerificationExpiry = tokenExpiry
    newUser.isEmailVerified = false

    // - upload avatar file to cloudinary
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
    const verifyEmailContent = emailVerificationMailgenContent(
        newUser.fullname,
        `${req.protocol}://${req.get("host")}/api/v1/auth/verify-email/${unHashedToken}`
    )

    await sendMail({ email: newUser?.email, subject: "Verify Email", mailgenContent: verifyEmailContent })

    // - send success status to user
    const createdUser = await User.findById(newUser._id, "-password -emailVerificationExpiry -emailVerificationToken -refreshToken -forgotPasswordToken -forgotPasswordTokenExpiry")

    if (!createdUser) {
        throw new ApiError(500, "Something went wrong while registering the user")
    }

    res.status(201).json(
        new ApiResponse(401, "User registered successfully", { newUser: createdUser })
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
    const hashedToken = hashToken(verificationToken)

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
    const accessToken = generateAccessToken(newUser)
    const refreshToken = generateRefreshToken(newUser)

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
    const hashedRefreshToken = hashToken(refreshToken)

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
    const { hashedToken, unHashedToken, tokenExpiry } = generateToken()

    newUser.emailVerificationToken = hashedToken
    newUser.emailVerificationExpiry = tokenExpiry

    await newUser.save({ validateBeforeSave: false })

    // send the new verification email to user
    const verificationUrl = `${req.protocol}://${req.get("host")}/api/v1/auth/verify-email/${unHashedToken}`
    const verificationMailContent = emailVerificationMailgenContent(newUser.fullname, verificationUrl)

    await sendMail({
        email: newUser?.email,
        subject: "Verify Email",
        mailgenContent: verificationMailContent
    })

    // save the user and send success response

    const createdUser = await User.findById(newUser._id, "-password -emailVerificationExpiry -emailVerificationToken -refreshToken -forgotPasswordToken -forgotPasswordTokenExpiry")

    res
        .status(201)
        .json(
            new ApiResponse(201, "Verification mail sent successfully", createdUser)
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
    if (user.isEmailVerified === false) {
        throw new ApiError(400, "User is not verified")
    }

    // check the password of the user
    const hashedPassword = user.password
    const matchPassword = await isPasswordMatch(password, hashedPassword)

    if (!matchPassword) {
        throw new ApiError(400, "Password not matched, please enter the valid password")
    }

    // assign access and refresh token to the user
    const refreshToken = generateRefreshToken(user)
    const accessToken = generateAccessToken(user)

    if (!refreshToken || !accessToken) {
        throw new ApiError(500, "Internal Server Error: while assigning the JWT tokens")
    }

    // send the access token to user via cookies
    const accessTokenCookieOptions = {
        httpOnly: true,
        secure: true,
        maxAge: 24 * 60 * 60 * 1000
    }

    const refreshTokenCookieOptions = {
        httpOnly: true,
        secure: true,
        maxAge: 7 * 24 * 60 * 60 * 1000
    }

    res.cookie("accessToken", accessToken, accessTokenCookieOptions)
    res.cookie("refreshToken", refreshToken, refreshTokenCookieOptions)

    // store the hashed refresh token in db
    const hashedRefreshToken = hashToken(refreshToken)

    user.refreshToken = hashedRefreshToken
    await user.save({ validateBeforeSave: false })

    // send success response to the user
    const loggedInUser = await User.findById(user._id, "-password -emailVerificationExpiry -emailVerificationToken -refreshToken -forgotPasswordToken -forgotPasswordTokenExpiry")

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
        sameSite: "none"
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

const refreshAccessToken = asyncHandler(async (req, res) => {
    // Get the incoming refresh Token from the cookie or db
    const incomingRefreshToken = req.cookie?.refreshToken || req.body?.refreshToken

    // validate the incoming refreshToken
    if (!incomingRefreshToken) {
        throw new ApiError(401, "Unauthorized Request")
    }

    // find user based on refreshTOken
    try {
        const decodedToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET)

        const user = await User.findById(decodedToken._id)

        // validate the user
        if (!user) {
            throw new ApiError(401, "Invalid Refresh Token")
        }

        // check if incoming refresh token is same as the refresh token attached in the user document
        // This shows that the refresh token is used or   not
        // Once it is used, we are replacing it with new refresh token below
        if (incomingRefreshToken !== user?.refreshToken) {
            // If token is valid but is used already
            throw new ApiError(401, "Refresh token is expired or used");
        }

        // generate fresh access and refresh Token
        const newAccessToken = generateAccessToken(user)
        const newRefreshToken = generateRefreshToken(user)

        const accessTokenCookieOptions = {
            httpOnly: true,
            secure: true,
            maxAge: 24 * 60 * 60 * 1000
        }

        const refreshTokenCookieOptions = {
            httpOnly: true,
            secure: true,
            maxAge: 7 * 24 * 60 * 60 * 1000
        }

        res.cookie("accessToken", newAccessToken, accessTokenCookieOptions)
        res.cookie("refreshToken", newRefreshToken, refreshTokenCookieOptions)

        // update the users refresh token in db
        user.refreshToken = newRefreshToken
        await user.save({ validateBeforeSave: false })

        // send success response to user
        return res
            .status(200)
            .json(
                new ApiResponse(
                    200,
                    { newAccessToken, newRefreshToken },
                    "Access token refreshed",
                ),
            );
    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid refresh token");
    }

})

const changeCurrentPassword = asyncHandler(async (req, res) => {
    // get the password and new Password from the body
    const { password, newPassword } = req.body

    // validate the fields
    if (!password && !newPassword) {
        throw new ApiError(400, "All fields are required")
    }

    // find user on basis of email
    const { _id } = req.user

    const user = await User.findById(_id)

    if (!user) {
        throw new ApiError(400, "User not found")
    }
    // hash new Password
    const hashedNewPassword = await hashPassword(newPassword)

    // validate the old password
    const hashedOldPassword = user.password

    const comparePassword = await isPasswordMatch(password, hashedOldPassword)

    if (!comparePassword) {
        throw new ApiError(400, "The old password is incorrect")
    }

    // match the old hashed password with the new ones
    const compareOldAndNewPassword = await isPasswordMatch(newPassword, hashedOldPassword)

    if (compareOldAndNewPassword === true) {
        throw new ApiError(400, "The old password and the new password shouldn't be same")
    }

    // save the new password in db
    user.password = hashedNewPassword
    await user.save({ validateBeforeSave: false })

    // logout the user
    const cookieOptions = {
        httpOnly: true,
        secure: true,
        sameSite: "none"
    }

    res.clearCookie("accessToken", cookieOptions)
    res.clearCookie("refreshToken", cookieOptions)

    // send success response to user
    res
        .status(201)
        .json(
            new ApiResponse(201, "New Password created successfully", null)
        )
})

const forgotPasswordRequest = asyncHandler(async (req, res) => {
    // get the email from the body
    const { email } = req.body
    if (!email) {
        throw new ApiError(400, "Email is Required")
    }

    // validate the email get the user from the email
    const user = await User.findOne({ email: email })
    if (!user) {
        throw new ApiError(400, "User not found")
    }

    console.log(user);

    // send the forgot password mail to the user
    const { hashedToken, unHashedToken, tokenExpiry } = generateToken()

    user.forgotPasswordToken = hashedToken
    user.forgotPasswordTokenExpiry = tokenExpiry
    await user.save({ validateBeforeSave: false })

    const forgotPasswordRequestUrl = `${req.protocol}://${req.get("host")}/api/v1/auth/reset-forgotten-password/${unHashedToken}`
    const forgotPasswordMailContent = forgotPasswordRequestMailGenContent(user.fullname, forgotPasswordRequestUrl)

    await sendMail({
        email: user?.email,
        subject: "Forgot the Password",
        mailgenContent: forgotPasswordMailContent
    })

    // send success res to user 
    const existedUser = await User.findById(user._id, "-password -emailVerificationExpiry -emailVerificationToken -refreshToken -forgotPasswordToken -forgotPasswordTokenExpiry")

    res
        .status(200)
        .json(
            new ApiResponse(200, "Forgot Password request sent successfully", existedUser)
        )
})

const resetForgottenPassword = asyncHandler(async (req, res) => {
    // get the forgot password token from the params
    const { forgotPasswordToken } = req.params
    if (!forgotPasswordToken) {
        throw new ApiError(404, "Forgot password token not found")
    }

    const hasedForgotPasswordToken = hashToken(forgotPasswordToken)



    // verfy the token and find the user based on token
    const user = await User.findOne({
        forgotPasswordToken: hasedForgotPasswordToken,
        forgotPasswordTokenExpiry: { $gt: Date.now() }
    })

    if (!user) {
        throw new ApiError(404, "Unauthorized token")
    }

    // get the password, confirmPassword from the body
    const { password, confirmPassword } = req.body
    if (!password && !confirmPassword) {
        throw new ApiError(400, "All fields are required")
    }

    // check password and confirmPasswords value
    if (password !== confirmPassword) {
        throw new ApiError(400, "Values of password and confirmPassword field should be same")
    }

    // save the password in db 
    const hashedPassword = await hashPassword(password)

    user.password = hashedPassword
    user.forgotPasswordToken = undefined
    user.forgotPasswordTokenExpiry = undefined

    user.save({ validateBeforeSave: false })

    // sent success response to the user
    const existedUser = await User.findById(user._id, "-password -emailVerificationExpiry -emailVerificationToken -refreshToken -forgotPasswordToken -forgotPasswordTokenExpiry")

    res
        .status(201)
        .json(
            new ApiResponse(201, "New Password Created Successfully", existedUser)
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

export { register, verifyUser, resendEmailVerification, login, logout, refreshAccessToken, changeCurrentPassword, forgotPasswordRequest, resetForgottenPassword, getUser }