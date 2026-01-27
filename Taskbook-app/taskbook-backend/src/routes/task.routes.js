import { Router } from "express";
import { isLoggedIn } from "../middlewares/auth.middleware.js";
import { createTask, getTasks, updateTaskAssignees, updateTaskDescription, updateTaskStatus, updateTaskTitle } from "../controllers/tasks.controllers.js";
import validate from "../middlewares/validate.middleware.js";
import { createTaskValidators, updateTaskAssigneesValidators, updateTaskDescriptionValidators, updateTaskStatusValidators, updateTaskTitleValidators } from "../validators/task.validations.js";
import { hasPermission } from "../middlewares/validateRole.middleware.js";
// import { uploadFileHandler } from "../middlewares/multer.middleware.js";

const router = Router()

router.use(isLoggedIn)

// router.route("/:projectId/createTask").post(hasPermission("create:task"), upload.array("attachments"), createTaskValidators(), validate, createTask)

router.route("/:projectId/allTasks").get(hasPermission("view:task"), getTasks)

router.route("/:projectId/:taskId").get(hasPermission("view:task"), getTasks)

router.route("/:projectId/:taskId/updateTaskTitle").patch(hasPermission("edit:task"), updateTaskTitleValidators(), validate, updateTaskTitle)

router.route("/:projectId/:taskId/updateTaskDesc").patch(hasPermission("edit:task"), updateTaskDescriptionValidators(), validate, updateTaskDescription)

router.route("/:projectId/:taskId/updateTaskStatus").patch(hasPermission("edit:task"), updateTaskStatusValidators(), validate, updateTaskStatus)

router.route("/:projectId/:taskId/updateTaskAssignees").patch(hasPermission("edit:task"), updateTaskAssigneesValidators(), validate, updateTaskAssignees)

export default router