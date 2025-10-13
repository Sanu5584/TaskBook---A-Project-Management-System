import { body } from "express-validator"

const createProjectValidators = () => {
    return [
        body('projectName')
            .isString()
            .trim()
            .notEmpty().withMessage("Project name is required")
            .isLength({ min: 3 }).withMessage("Username must required minimum length of 3 characters")
            .isLength({ max: 32 }).withMessage("Username must contains less than 32 characters"),

        body("projectDescription")
            .isString()
            .notEmpty().withMessage("Project description is required")
            .isLength({ min: 15 }).withMessage("Username must required minimum length of 15 characters")
            .isLength({ max: 200 }).withMessage("Username must contains less than 200 characters"),
    ]
}

const updateProjectValidators = () => {
    return [
        body('projectName')
            .isString()
            .trim()
            .notEmpty().withMessage("Project name is required")
            .isLength({ min: 3 }).withMessage("Username must required minimum length of 3 characters")
            .isLength({ max: 32 }).withMessage("Username must contains less than 32 characters")
            .optional(),

        body("projectDescription")
            .isString()
            .notEmpty().withMessage("Project description is required")
            .isLength({ min: 15 }).withMessage("Username must required minimum length of 15 characters")
            .isLength({ max: 200 }).withMessage("Username must contains less than 200 characters")
            .optional(),
    ]
}

const addMemberToProjectValidators = () => {
    return [
        body("email")
            .isString()
            .trim()
            .notEmpty().withMessage("Email is Required")
            .isEmail().withMessage("Email not found")
            .isLowercase().withMessage("Email is should be in lower case only"),
        body("role")
            .isString()
            .trim()
            .notEmpty().withMessage("Role is Required")
    ]
}

const updateMemberRoleValidator = () => {
    return [
        body('newRole')
            .trim()
            .isString()
            .notEmpty().withMessage("Role is Required")
    ]
}

export { createProjectValidators, updateProjectValidators, addMemberToProjectValidators, updateMemberRoleValidator }