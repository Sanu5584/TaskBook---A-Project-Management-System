import { ApiError } from "../utils/api-error.utils.js";
import { ApiResponse } from "../utils/api-response.utils.js";
import { asyncHandler } from "../utils/async-handler.utils.js";
import Project from "../models/project.model.js"
import ProjectMember from "../models/projectmember.model.js"
import User from "../models/user.model.js";
import mongoose from "mongoose";
import { AvailableProjectStatus, AvailableUserRolesPermission, userRolesEnum } from "../utils/constants.utils.js";

const createProject = asyncHandler(async (req, res) => {

    // get project_name, project_description, project_members, project_deadline from the body
    const { projectName, projectDescription, projectDueDate, uniqueProjectIdentifier, status } = req.body

    // validate the input data
    if (!projectName || !projectDescription) {
        throw new ApiError(400, "All fields marked with * is required")
    }

    if (!AvailableProjectStatus.includes(status)) {
        throw new ApiError(400, "Project status type is irrelavant")
    }

    // const dueDate = new Date(projectDueDate)

    // console.log("Due Date ==== ", dueDate);
    // console.log(typeof dueDate);

    // create new project in db 
    const newProject = await Project.create({
        projectName: projectName,
        uniqueProjectIdentifier: uniqueProjectIdentifier,
        projectDescription: projectDescription,
        createdBy: req.user?._id,
        projectDueDate: projectDueDate,
        // projectRoles: projectRoles, // enhance by making it a global and patch type method
        status: status
        // addMembers: projectMembers
    })

    // create new projectMember in db
    const newProjectMember = await ProjectMember.create({
        user: req.user._id,
        project: newProject._id,
        role: userRolesEnum.ProjectAdmin
    })  

    // save the db
    await newProject.save()
    await newProjectMember.save()

    // send success response to user
    return res
        .status(201)
        .json(
            new ApiResponse(201, `New Project "${projectName}" created successfully`, { newProject, newProjectMember })
        )

})

const addMemberToProject = asyncHandler(async (req, res) => {
    // get member's email, avatar, fullname, role from the body
    const { email, role } = req.body

    // find user based on email
    const user = await User.findOne({
        email: email
    })

    if (!user) {
        throw new ApiError(404, "User not found")
    }

    // get projectId from the params
    const { projectId } = req.params

    if (!projectId) {
        throw new ApiError(404, "Invalid Project Access Request")
    }

    // find project on basis of projectId
    const project = await Project.findById(projectId)

    // check if user is already exists or not
    const alreadyExistedMember = await ProjectMember.findOne({ user: user._id, project: projectId })

    if (alreadyExistedMember) {
        throw new ApiError(400, `${user.username} is already exists in the ${project.projectName}`)
    }

    // create the project member by adding projectId, userid, role
    const newProjectMember = await ProjectMember.create(
        {
            project: projectId,
            user: user._id,
            role: role
        }
    )
    // save the db
    await newProjectMember.save()

    // return success response to user
    return res
        .status(201)
        .json(
            new ApiResponse(201, "New member in project added successfully", newProjectMember)
        )
})

const getProjectMembers = asyncHandler(async (req, res) => {
    // get projectID from the params
    const { projectId } = req.params

    if (!projectId) {
        throw new ApiError(404, "Project Not Found")
    }

    // find project by projectId
    const project = await Project.findById(projectId)

    // get the projectMembers associated to the project using aggregation framework 
    const getAllProjectMembers = await ProjectMember.aggregate(
        [
            {
                $match: {
                    project: new mongoose.Types.ObjectId(projectId)
                }
            },
            {
                $lookup: {
                    from: "users",
                    localField: "user",
                    foreignField: "_id",
                    as: "user",
                    pipeline: [
                        {
                            $project: {
                                _id: 1,
                                avatar: 1,
                                username: 1,
                                fullname: 1
                            }
                        }
                    ]
                }
            },
            {
                $addFields: {
                    user: {
                        $arrayElemAt: ["$user", 0]
                    }
                }
            },
            {
                $project: {
                    project: 1,
                    user: 1,
                    role: 1,
                    createdAt: 1,
                    updatedAt: 1,
                    _id: 0
                }
            }
        ]
    )

    console.log("All project members:---------", getAllProjectMembers);


    return res
        .status(200)
        .json(
            new ApiResponse(200, `All project members of ${project.projectName} fetched Successfully`, getAllProjectMembers)
        )
})

const updateMemberRole = asyncHandler(async (req, res) => {
    // get projectId, userId from the params
    const { projectId, userId } = req.params

    // verify the projectId
    if (!projectId || !userId) {
        throw new ApiError(400, "Project or User not found")
    }

    // get newRole from the body
    const { newRole } = req.body

    if (!newRole) {
        throw new ApiError(400, "New Role was required to update the role of the member")
    }

    // validate the role that is it available in the roleEnum
    const validateRole = AvailableUserRolesPermission.includes(newRole)

    if (!validateRole) {
        throw new ApiError(400, "Role not exists")
    }

    // find the user in db and update the role to new one
    let updatedProjectMember = await ProjectMember.findOneAndUpdate(
        {
            user: userId,
            project: projectId
        },
        {
            role: newRole
        },
        { new: true, runValidators: true }
    )

    if (!updatedProjectMember) {
        throw new ApiError(404, "Member not found")
    }

    updatedProjectMember.role = newRole
    await updatedProjectMember.save()

    // return success res to user
    return res
        .status(200)
        .json(
            new ApiResponse(200, `Member role updated successfully`, updatedProjectMember)
        )
})

const removeMember = asyncHandler(async (req, res) => {
    // get the projectId, userId from the params
    const { projectId, userId } = req.params

    if (!projectId || !userId) {
        throw new ApiError(400, "Project or User not found")
    }

    // find the project member from the db
    const projectMember = await ProjectMember.deleteOne({
        user: new mongoose.Types.ObjectId(userId),
        project: new mongoose.Types.ObjectId(projectId)
    })

    // send success response to user
    return res
        .status(200)
        .json(
            new ApiResponse(200, `Member removed from project successfully`, null)
        )
})

const getProjects = asyncHandler(async (req, res) => {
    // get user id from the req
    const userId = req.user?._id

    // verify the user
    if (!userId) {
        throw new ApiError(404, "User is not authenticated, if you are already a user please login again")
    }
    // get all projects
    // match all the projects the members was associated to
    const allProjects = await ProjectMember.aggregate(
        [
            // it matches all documents of project members with given user id
            {
                $match: {
                    user: new mongoose.Types.ObjectId(userId)
                }
            },
            // it connects Project collection's document's field named _id with ProjetMember collection's document's field named project and gives all matched documents in an array named as allProjects
            {
                $lookup: {
                    from: "projects",
                    localField: "project",
                    foreignField: "_id",
                    as: "allProjects",
                    pipeline: [
                        {
                            $lookup: {
                                from: "projectmembers",
                                localField: "_id",
                                foreignField: "project",
                                as: "allProjectMembers"
                            }
                        },
                        {
                            $addFields: {
                                totalProjectMembers: {
                                    $size: "$allProjectMembers"
                                }
                            }
                        }
                    ]
                }
            },
            {
                $unwind: {
                    path: "$allProjects"
                }
            },
            {
                $project: {
                    _id: 0,
                    allProjects: {
                        _id: 1,
                        projectName: 1,
                        projectDescription: 1,
                        totalProjectMembers: 1,
                        uniqueProjectIdentifier: 1,
                        createdAt: 1,
                        projectDueDate: 1,
                        createdBy: 1,
                        status: 1
                    },
                    role: 1,
                }
            }
        ]
    )

    // send success response to the user
    return res
        .status(200)
        .json(
            new ApiResponse(200, "All Projects Fetched Successfully", allProjects)
        )
})

const getProjectById = asyncHandler(async (req, res) => {

    // get the projectId from the params
    const { projectId } = req.params

    // validate the project id
    if (!projectId) {
        throw new ApiError(404, "Project Id is not valid")
    }

    // get the project from the db
    const project = await Project.findById(projectId)

    if (!project) {
        throw new ApiError(404, "Project Id is not valid")
    }

    // send success response to user
    return res
        .status(200)
        .json(
            new ApiResponse(200, `${project.projectName} Data Fetched Successfully`, project)
        )

})

const updateProject = asyncHandler(async (req, res) => {

    // get projectname and projectDescription from the body
    const { projectName, projectDescription, projectDueDate, uniqueProjectIdentifier } = req.body
    const { projectId } = req.params

    // validate the project Id, name and desc
    if (!projectId) {
        throw new ApiError(404, "Project not found")
    }

    // update the value in db
    const updatedProject = await Project.findByIdAndUpdate(
        projectId,
        {
            projectName: projectName,
            projectDescription: projectDescription,
            projectDueDate: projectDueDate,
            uniqueProjectIdentifier: uniqueProjectIdentifier
        },
        { new: true, runValidators: true }
    )

    if (!updatedProject) {
        throw new ApiError(404, "Project not found")
    }

    // send success response to user
    return res
        .status(202)
        .json(
            new ApiResponse(202, "Project Updated Successfully", updatedProject)
        )
})

const updateProjectStatus = asyncHandler(async (req, res) => {
    // get the project status from the body
    const { status } = req.body

    // get the projectid from the params
    const { projectId } = req.params

    // validate the project status and project id
    if (!projectId) {
        throw new ApiError(400, "Invalid project id")
    }

    if (!AvailableProjectStatus.includes(status)) {
        throw new ApiError(400, "Invalid status type")
    }

    // get the project from the db and update the status of the project
    const project = await Project.findByIdAndUpdate(projectId,
        {
            status: status
        },
        { new: true, runValidators: true }
    )

    if (!project) {
        throw new ApiError(404, "Project not found")
    }

    // send success response to user
    res
        .status(202)
        .json(
            new ApiResponse(202, "Project status updated successfully", project.status)
        )
})

const deleteProject = asyncHandler(async (req, res) => {

    // get the projectId from the params
    const { projectId } = req.params

    // validate the projectId
    if (!projectId) {
        throw new ApiError(404, "Project not found")
    }

    // delete the project from the db
    const project = await Project.findById(projectId)

    if (!projectId) {
        throw new ApiError(404, "Project not found")
    }


    const deletedProjectName = project.projectName

    await Project.findByIdAndDelete(projectId)

    // send success response to user
    return res
        .status(202)
        .json(
            new ApiResponse(202, `${deletedProjectName} deleted successfully`, null)
        )

})

export { createProject, getProjects, getProjectById, updateProject, updateProjectStatus, deleteProject, getProjectMembers, addMemberToProject, updateMemberRole, removeMember }