import { body } from "express-validator"
import { AvailableTaskStatus } from "../utils/constants.utils.js"

const createTaskValidators = () => {
    return [
        body("title")
            .trim()
            .notEmpty().withMessage("Task Title is required")
            .isString()
            .isLength({ min: 3 }).withMessage("Task Title must required minimum length of 3 characters")
            .isLength({ max: 320 }).withMessage("Task title must contains less than 320 characters"),
        body("description")
            .trim()
            .optional()
            .isString()
            .isLength({ max: 600 }).withMessage("Task description must contains less than 600 characters"),
        body("assignedTo")
            .trim()
            .optional()
            .isEmail(),
        body("status")
            .trim()
            .notEmpty().withMessage("Task status is required")
            .isString()
            .isIn(AvailableTaskStatus).withMessage("Task Status is Invalid"),
    ]
}

const updateTaskTitleValidators = () => {
    return [
        body("title")
            .trim()
            .notEmpty().withMessage("New Task Title is required to update existing one")
            .isString()
            .isLength({ min: 3 }).withMessage("Task Title must required minimum length of 3 characters")
            .isLength({ max: 320 }).withMessage("Task title must contains less than 320 characters"),
    ]
}

const updateTaskDescriptionValidators = () => {
    return [
        body("description")
            .optional()
            .trim()
            .isString()
            .isLength({ max: 600 }).withMessage("Task description must contains less than 600 characters"),
    ]
}

const updateTaskStatusValidators = () => {
    return [
        body("status")
            .trim()
            .notEmpty().withMessage("Task status is required")
            .isString()
            .isIn(AvailableTaskStatus).withMessage("Task Status is Invalid"),
    ]
}

const updateTaskAssigneesValidators = () => {
    return [
        body("assignedTo")
            .trim()
            .optional()
            .isEmail(),
    ]
}

const createSubTaskValidators = () => {
    return [
        body("subTaskTitle")
            .trim()
            .notEmpty().withMessage("SubTask Title is required")
            .isString()
            .isLength({ min: 3 }).withMessage("SubTask Title must required minimum length of 3 characters")
            .isLength({ max: 320 }).withMessage("SubTask title must contains less than 320 characters"),
        body("subTaskDescription")
            .trim()
            .optional()
            .isString()
            .isLength({ max: 600 }).withMessage("SubTask description must contains less than 600 characters"),
        body("subTaskCompletionStatus")
            .trim()
            .notEmpty().withMessage("SubTask status is required")
            .isString()
            .isIn(AvailableTaskStatus).withMessage("SubTask Status is Invalid"),
    ]
}

const updateSubTaskTitleValidators = () => {
    return [
        body("subTaskTitle")
            .trim()
            .notEmpty().withMessage("SubTask Title is required")
            .isString()
            .isLength({ min: 3 }).withMessage("SubTask Title must required minimum length of 3 characters")
            .isLength({ max: 320 }).withMessage("SubTask title must contains less than 320 characters"),
    ]
}

const updateSubTaskDescriptionValidators = () => {
    return [
        body("description")
            .optional()
            .trim()
            .isString()
            .isLength({ max: 600 }).withMessage("Task description must contains less than 600 characters"),
    ]
}

const subTaskIsCompletedValidators = () => {
    return [
        body("status")
            .trim()
            .notEmpty().withMessage("Task status is required")
            .isString()
            .isIn(AvailableTaskStatus).withMessage("Task Status is Invalid"),
    ]
}

export { createTaskValidators, updateTaskTitleValidators, updateTaskDescriptionValidators, updateTaskStatusValidators, updateTaskAssigneesValidators, createSubTaskValidators, updateSubTaskTitleValidators, updateSubTaskDescriptionValidators, subTaskIsCompletedValidators }