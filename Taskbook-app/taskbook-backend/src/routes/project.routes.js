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
    removeMember,
    updateProjectStatus
} from "../controllers/project.controllers.js";
import {
    addMemberToProjectValidators, createProjectValidators, updateMemberRoleValidators, updateProjectStatusValidators, updateProjectValidators
} from "../validators/project.validations.js";
import validate from "../middlewares/validate.middleware.js";
import { isLoggedIn } from "../middlewares/auth.middleware.js";
import { hasPermission } from "../middlewares/validateRole.middleware.js";

const router = Router()

router.use(isLoggedIn)


router.route("/create").post(createProjectValidators(), validate, createProject)

router.route("/:projectId/project-members").get(hasPermission('view:project'), getProjectMembers)

router.route("/:projectId/add-member").post(hasPermission('addMember:project'), addMemberToProjectValidators(), validate, addMemberToProject)

router.route("/:projectId/:userId/update-role").patch(hasPermission('updateMember:project'), updateMemberRoleValidators(), validate, updateMemberRole)

router.route("/:projectId/:userId/remove").delete(hasPermission('removeMember:project'), removeMember)

router.route("/").get(getProjects)

router.route("/:projectId").get(hasPermission('view:project'), getProjectById)

router.route("/:projectId/update").patch(hasPermission('edit:project'), updateProjectValidators(), validate, updateProject)

router.route("/:projectId/update-status").patch(hasPermission('edit:project'), updateProjectStatusValidators(), validate, updateProjectStatus)

router.route("/:projectId/delete").delete(hasPermission('delete:project'), deleteProject)


export default router