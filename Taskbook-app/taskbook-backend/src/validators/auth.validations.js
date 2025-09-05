import { body } from "express-validator"

const userRegistrationValidator = () => {
    return [
        body("username")
            .trim()
            .notEmpty().withMessage("Username is Required")
            .isLowercase().withMessage("Username is should be in lower case only")
            .isLength({ min: 3 }).withMessage("Username must required minimum length of 3 characters")
            .isLength({ max: 32 }).withMessage("Username must contains less than 32 characters"),
        body("email")
            .trim()
            .isEmail().withMessage("Email not found")
            .notEmpty().withMessage("Email is Required")
            .isLowercase().withMessage("Email is should be in lower case only"),
        body("password")
            .trim()
            .isEmpty().withMessage("Password not Found")
            .isLength({ min: 8 }).withMessage("Password must be of minimum 8 characters")
            .isLength({ max: 16 }).withMessage("Password must contains less than 16 characters"),
        body("fullname")
            .trim()
            .notEmpty().withMessage("Fullname is Required")
    ]
}

export { userRegistrationValidator }