import { Router } from "express";

import {
    createProject,
    getProjects,
    getProjectById,
    updateProject,
    deleteProject,
    getProjectMembers,
    addMemberToProject,
    updateMemberRole,
    removeMember
} from "../controllers/project.controllers.js";
import {
    addMemberToProjectValidators, createProjectValidators, updateMemberRoleValidator, updateProjectValidators
} from "../validators/project.validations.js";
import validate from "../middlewares/validate.middleware.js";
import { isLoggedIn } from "../middlewares/auth.middleware.js";

const router = Router()

router.use(isLoggedIn)

router.route("/create").post(createProjectValidators(), validate, createProject)
router.route("/:projectId/project-members").get(getProjectMembers)
router.route("/:projectId/add-member").post(addMemberToProjectValidators(), validate, addMemberToProject)
router.route("/:projectId/:userId/update-role").patch(updateMemberRoleValidator(), validate, updateMemberRole)
router.route("/:projectId/:userId/remove").delete(removeMember)
router.route("/").get(getProjects)
router.route("/:projectId").get(getProjectById)
router.route("/:projectId/update").patch(updateProjectValidators(), validate, updateProject)
router.route("/:projectId/delete").delete(deleteProject)


export default router