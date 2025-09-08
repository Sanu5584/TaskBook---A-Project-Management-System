import { ApiError } from "../utils/api-error.utils.js"
import { ApiResponse } from "../utils/api-response.utils.js"
import { asyncHandler } from "../utils/async-handler.utils.js"
import { User } from "../models/user.model.js"
import { sendMail, emailVerificationMailgenContent } from "../services/mailing.service.js"
import { uploadOnCloudinary } from "../services/cloudinary.service.js"

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
    const createdUser = await User.findById(newUser._id, "-password -emailVerificationExpiry -emailVerificationToken -refreshToken")

    if (!createdUser) {
        throw new ApiError(500, "Something went wrong while registering the user")
    }

    res.status(401).json(
        new ApiResponse(401, "User registered successfully", { newUser: createdUser })
    )

})

export { register }