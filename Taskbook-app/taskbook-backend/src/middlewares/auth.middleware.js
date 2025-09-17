import { ApiError } from "../utils/api-error.utils.js";
import { asyncHandler } from "../utils/async-handler.utils.js";

import jwt from "jsonwebtoken"

const isLoggedIn = asyncHandler(async (req, res, next) => {
    // get accessToken from the user's cookie
    const accessToken = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ", "")
    // validate the cookie and user based on the accessToken

    if (!accessToken) {
        throw new ApiError(401, "Authentication Failed")
    }

    // check the accessToken is expired or not
    const decodedUser = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET)
    console.log("decoded data :", decodedUser);

    // add the user._id into the req object and next
    req.user = decodedUser
    next()
})

export { isLoggedIn }