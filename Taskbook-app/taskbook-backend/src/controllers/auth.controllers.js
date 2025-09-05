import { asyncHandler } from "../utils/async-handler.utils.js"

const register = asyncHandler(async (req, res) => {

    // - get data from the body
    const { fullname, username, email, password } = req.body

    // - validate the data we get from the user
    // - check if user already exists or not
    // - hash the password and store it in db
    // - generate a verification link
    // - save the verfication token in db
    // - sent verification token to user via email 
    // - save the user and send success status to user

})

export { register }