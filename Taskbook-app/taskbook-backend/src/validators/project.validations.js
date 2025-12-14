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

        body("uniqueProjectIdentifier")
            .isString()
            .trim()
            .notEmpty().withMessage("Project name is required")
            .isLength({ min: 3 }).withMessage("Username must required minimum length of 3 characters")
            .isLength({ max: 32 }).withMessage("Username must contains less than 32 characters"),

        body("projectDueDate")
            .optional()
            .isString()
            .trim(),

        body("status")
            .isString()
            .notEmpty()
            .trim()
    ]
}

const updateProjectValidators = () => {
    return [
        body('projectName')
            .isString()
            .trim()
            .notEmpty().withMessage("Project name is required")
            .isLength({ min: 3 }).withMessage("Project name must required minimum length of 3 characters")
            .isLength({ max: 32 }).withMessage("Project name must contains less than 60 characters")
            .optional(),

        body("projectDescription")
            .isString()
            .notEmpty().withMessage("Project description is required")
            .isLength({ min: 15 }).withMessage("Project description must required minimum length of 15 characters")
            .isLength({ max: 500 }).withMessage("Project description must contains less than 200 characters")
            .optional(),

        body("uniqueProjectIdentifier")
            .isString()
            .trim()
            .notEmpty().withMessage("Project name is required")
            .isLength({ min: 3 }).withMessage("Username must required minimum length of 3 characters")
            .isLength({ max: 32 }).withMessage("Username must contains less than 32 characters"),

        body("projectDueDate")
            .isDate()
            .trim()
            .optional()
    ]
}

const updateProjectStatusValidators = () => {
    return [
        body("status")
            .isString()
            .notEmpty()
            .trim()
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

const updateMemberRoleValidators = () => {
    return [
        body('newRole')
            .trim()
            .isString()
            .notEmpty().withMessage("Role is Required")
    ]
}

export { createProjectValidators, updateProjectValidators, addMemberToProjectValidators, updateMemberRoleValidators, updateProjectStatusValidators }