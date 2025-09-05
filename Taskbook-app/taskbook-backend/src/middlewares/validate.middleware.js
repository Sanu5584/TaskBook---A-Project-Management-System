import { validationResult } from "express-validator";
import { asyncHandler } from "../utils/async-handler.utils.js";
import { ApiError } from "../utils/api-error.utils.js";


/************* Try and test out the methods in express-validators **************/

const validate = asyncHandler(async function (req, res, next) {
    const errors = validationResult(req)

    console.log(errors); //! Log it to see what was present in the errors variable
    
    if (!errors) {
        return next()
    }

    const extractedError = []
    errors.array().map((err) => {
        extractedError.push({
            [err.path]: err.msg
        })
    })

    throw new ApiError(422, "Recieved data is not valid", extractedError)
})

export default validate