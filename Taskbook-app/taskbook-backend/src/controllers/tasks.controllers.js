import { asyncHandler } from "../utils/async-handler.utils.js";
import { ApiError } from "../utils/api-error.utils.js"
import Task from "../models/task.model.js"
import Project from "../models/project.model.js"
import Subtask from "../models/subtask.model.js"
import Attachments from "../models/attachments.model.js"
import { uploadOnCloudinary, deleteFromCloudinary } from "../configs/cloudinary.config.js";
import mongoose from "mongoose";
import { ApiResponse } from "../utils/api-response.utils.js";
import { AvailableTaskStatus } from "../utils/constants.utils.js";
import ProjectMember from "../models/projectmember.model.js";

const createTask = asyncHandler(async (req, res) => {
    // get title, description, assignedTo, status from the body
    const { title, description, assignedTo, status } = req.body

    // get the user id from the req
    const userId = req.user?._id
    if (!userId) {
        throw new ApiError(400, "Unauthenticated Request")
    }

    // get the projectId from the params
    const { projectId } = req.params

    // validate the input data and projectId
    if (!projectId) {
        throw new ApiError(404, "Unauthorized Request")
    }

    // check that the status's value is presents in the AvailableTaskStatus
    if (!AvailableTaskStatus.includes(status)) {
        throw new ApiError(400, "Invalid task status")
    }

    //* // check the assigning member is part of project or not
    // const isProjectMember = await ProjectMember.aggregate(
    //     // match the project(now we have the list of all project members) ---> 
    //     [
    //         {
    //             $match: {
    //                 project: new mongoose.Types.ObjectId(projectId)
    //             }
    //         },
    //         {
    //             $lookup: {
    //                 from: "users",
    //                 localField: "user",
    //                 foreignField: "_id",
    //                 as: "projectMember",
    //                 pipeline: [  
    //                     {
    //                         $project: {
    //                             avatar: 1,
    //                             email: 1,
    //                             role: 1
    //                         }
    //                     }
    //                 ]
    //             }
    //         },
    //         {
    //             $match: {
    //                 project: new mongoose.Types.ObjectId(projectId),
    //                 user: "$projectMember.email"
    //             }
    //         },
    //         {
    //             $project: {
    //                 user: 1,
    //                 projectMember: 1,
    //                 project: 1,
    //             }
    //         }
    //     ]
    // )

    // console.log("Project Member checking", isProjectMember);
    // console.log(`AssignedTo value: ${assignedTo} --- filtered Value: ${isProjectMember}`);

    // create task in db
    const createTask = await Task.create({
        title: title,
        description: description,
        project: projectId,
        assignedTo: assignedTo,
        assignedBy: userId,
        status: status,
    })

    // add attachments
    // ---- get the files from the body
    const files = req?.files || []

    console.log("Files in create task controller: ", files);

    //  process all files and upload to cloudinary
    const attachments = await Promise.all(
        files.map(async (file) => {
            const result = await uploadOnCloudinary(file.path)
            console.log("result : ", result);
            return {
                url: result?.secure_url,
                name: file.name,
                originalFileName: result?.original_filename,
                mimetype: file.mimetype,
                publicId: result?.public_id,
                size: (file.size * 1024 * 1024),
            }
        })
    )

    console.log("Attachments : ", attachments);

    const saveAttachments = await Attachments.create({
        attachments: attachments,
        project: projectId,
        task: createTask._id,
        uploadedBy: userId,
    })

    // save attachments id in the task collection
    createTask.attachments = saveAttachments._id

    await createTask.save()

    console.log("save Attachments ---- ", saveAttachments);


    // send the success response to user

    res
        .status(201)
        .json(
            new ApiResponse(201, `${title} Created Successfully`, { createTask, saveAttachments })
        )
})

const getTasks = asyncHandler(async (req, res) => {
    // get projectId from the params
    const { projectId } = req.params
    if (!projectId) {
        throw new ApiError(404, "Project Not Found or Unauthorized Request")
    }

    // get all the tasks associated to user with metadata like task status, title, assignees, assignedBy, sub task counts 
    const allTasks = await Task.aggregate(
        [
            {
                // match all the tasks associated to project
                $match: {
                    project: new mongoose.Types.ObjectId(projectId)
                }
            },
            {
                $lookup: {
                    from: "attachments",
                    localField: "attachments",
                    foreignField: "_id",
                    as: "attachmentsByTask"
                }
            },
            {
                $unwind: {
                    path: "$attachmentsByTask"
                }
            },
            {
                $lookup: {
                    from: "projects",
                    localField: "project",
                    foreignField: "_id",
                    as: "projectInfo"
                }
            },
            {
                $unwind: {
                    path: "$projectInfo"
                }
            },
            {
                $addFields: {
                    attachmentsCount: {
                        $cond: {
                            if: { $isArray: "$attachmentsByTask.attachments" },
                            then: { $size: "$attachmentsByTask.attachments" },
                            else: []
                        }
                    }
                }
            },
            {
                // lookup for the assignedBy user to get the user's name and avatar
                $lookup: {
                    from: "users",
                    localField: "assignedBy",
                    foreignField: "_id",
                    as: "assignedByInfo"
                }
            },
            {
                // unwind assignedByInfo field
                $unwind: {
                    path: "$assignedByInfo"
                }
            },
            {
                //lookup for assignedTo users to get that user's names and avatars
                $lookup: {
                    from: "users",
                    localField: "assignedTo",
                    foreignField: "email",
                    as: "assignedToInfo"
                }
            },
            {
                // unwind assignedToInfo field
                $unwind: {
                    path: "$assignedToInfo"
                }
            },
            {
                $lookup: {
                    from: "subtasks",
                    localField: "task",
                    foreignField: "_id",
                    as: "subTasksInfo",
                    pipeline: [
                        {
                            $unwind: {
                                path: "$subTaskInfo"
                            }
                        },
                        {
                            $addFields: {
                                subTasksCount: {
                                    $sum: "$subTaskInfo"
                                }
                            }

                        }
                    ]
                }
            },
            {
                $project: {
                    _id: 1,
                    title: 1,
                    status: 1,
                    assignedBy: 1,
                    assignedTo: 1,
                    subTasksCount: 1,
                    attachmentsCount: 1,
                    projectId: "$projectInfo._id",
                    projectName: "$projectInfo.projectName"
                }
            }
        ]
    )

    console.log("All Tasks ---- ", allTasks)

    if (!allTasks) {
        throw new ApiError(404, "No tasks created yet")
    }

    return res
        .status(200)
        .json(
            new ApiResponse(200, "All tasks fetched successfully", allTasks)
        )

})

const getTaskById = asyncHandler(async (req, res) => {

    // get projectId and taskId from the params
    const { projectId, taskId } = req.params

    if (!projectId) {
        throw new ApiError(404, "Project Not Found")
    }
    if (!taskId) {
        throw new ApiError(404, "Task Not Found")
    }

    // get the task from the db
    const task = await Task.aggregate(
        [
            {
                $match: {
                    _id: new mongoose.Types.ObjectId(taskId)
                }
            },
            {
                $lookup: {
                    from: "projects",
                    localField: "project",
                    foreignField: "_id",
                    as: "projectInfo"
                }
            },
            {
                $unwind: {
                    path: "$projectInfo"
                }
            },
            {
                $lookup: {
                    from: "users",
                    localField: "assignedBy",
                    foreignField: "_id",
                    as: "createdBy"
                }
            },
            {
                $unwind: {
                    path: "$createdBy"
                }
            },
            {
                $lookup: {
                    from: "users",
                    localField: "assignedTo",
                    foreignField: "email",
                    as: "assignees"
                }
            },
            {
                $unwind: {
                    path: "$assignees"
                }
            },
            {
                $project: {
                    title: 1,
                    description: 1,
                    status: 1,
                    projectInfo: {
                        projectName: 1,
                    },
                    createdBy: {
                        avatar: 1,
                        username: 1,
                        email: 1
                    },
                    assignees: {
                        avatar: 1,
                        username: 1,
                        email: 1
                    },
                    status: 1,
                    attachments: 1,
                    updatedAt: 1
                }
            }
        ]
    )

    if (!task) {
        throw new ApiError(404, "Task Not Found or Unauthorized Request")
    }

    // send success response to user
    res
        .status(200)
        .json(
            new ApiResponse(200, "Task fetched Successfully", task)
        )
})

const updateTaskTitle = asyncHandler(async (req, res) => {
    //  get the task id from the params
    const { taskId, projectId } = req.params

    // get the task name from the body
    const { title } = req.body

    if (!projectId) {
        throw new ApiError(400, "Project not found or Unauthorized access")
    }

    if (!mongoose.Types.ObjectId.isValid(taskId)) {
        throw new ApiError(400, "Task does not exists")
    }

    // check if the task exists or not
    const existedTask = await Task.findById(taskId)
    if (!existedTask) {
        throw new ApiError(400, "Task not found or Unauthorized access")
    }

    // update the task title in db
    if (!title || title === undefined || title === null) {
        res
            .status(200)
            .json(
                new ApiResponse(200, "No changes were found", null)
            )
    }

    existedTask.title = title

    await existedTask.save()

    res
        .status(200)
        .json(
            new ApiResponse(200, "Task's title updated successfully", existedTask)
        )
})

const updateTaskDescription = asyncHandler(async (req, res) => {
    //  get the task id from the params
    const { taskId, projectId } = req.params
    const { description } = req.body

    if (!projectId) {
        throw new ApiError(400, "Project not found or Unauthorized access")
    }


    if (!mongoose.Types.ObjectId.isValid(taskId)) {
        throw new ApiError(400, "Task does not exists")
    }

    // check if the task exists or not
    const existedTask = await Task.findById(taskId)
    if (!existedTask) {
        throw new ApiError(400, "Task not found or Unauthorized access")
    }

    // update the task title in db
    if (description.length < 0) {
        res
            .status(200)
            .json(
                new ApiResponse(200, "No changes were found", null)
            )
    }

    existedTask.description = description

    await existedTask.save()

    res
        .status(200)
        .json(
            new ApiResponse(200, "Task's description updated successfully", existedTask)
        )
})

const updateTaskStatus = asyncHandler(async (req, res) => {
    //  get the task id from the params
    const { taskId, projectId } = req.params
    const { status } = req.body

    if (!projectId) {
        throw new ApiError(400, "Project not found or Unauthorized access")
    }


    if (!mongoose.Types.ObjectId.isValid(taskId)) {
        throw new ApiError(400, "Task does not exists")
    }

    // check if the task exists or not
    const existedTask = await Task.findById(taskId)
    if (!existedTask) {
        throw new ApiError(400, "Task not found or Unauthorized access")
    }

    // check that the value of status is from defined enum only 
    if (!AvailableTaskStatus.includes(status)) {
        throw new ApiError(400, "Status should be from the available dropdown")
    }

    // update task status in db
    existedTask.status = status
    await existedTask.save()

    res
        .status(200)
        .json(
            new ApiResponse(200, "Task status updated successfully", existedTask)
        )
})

const updateTaskAssignee = asyncHandler(async (req, res) => {
    //  get the task id from the params
    const { taskId, projectId } = req.params
    const { assignedTo } = req.body

    if (!projectId) {
        throw new ApiError(400, "Project not found or Unauthorized access")
    }

    if (!mongoose.Types.ObjectId.isValid(taskId)) {
        throw new ApiError(400, "Task does not exists")
    }

    // check if the task exists or not
    const existedTask = await Task.findById(taskId)
    if (!existedTask) {
        throw new ApiError(400, "Task not found or Unauthorized access")
    }

    // check if assignedTo value is from the projectMember's enum only 
    const isProjectMember = await ProjectMember.aggregate(
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
                    as: "userDetails",
                }
            },
            {
                $unwind: {
                    path: "$userDetails"
                }
            },
            {
                $match: {
                    project: new mongoose.Types.ObjectId(projectId),
                    "userDetails.email": assignedTo
                }
            },
            {
                $project: {
                    user: 1,
                    ProjectMember: 1,
                    project: 1
                }
            }
        ]
    )

    // Convert result to boolean
    const isValidMember = isProjectMember.length > 0

    console.log("Project Member checking", isProjectMember);

    console.log(`AssignedTo value: ${assignedTo} --- Is Valid Member: ${isValidMember}`);

    // update the assignee
    if (!isValidMember) {
        throw new ApiError(400, "Assignee should be from the project members only")
    }

    existedTask.assignedTo = assignedTo
    existedTask.save()

    // send success response to user
    res
        .status(200)
        .json(
            new ApiResponse(200, "Task assignee updated successfully", existedTask)
        )
})

const createSubTask = asyncHandler(async (req, res) => {
    // get the projectId and taskId from the params
    const { taskId, projectId } = req.params

    // get user from the req and validate the user
    const userId = req.user?._id
    if (!userId) {
        throw new ApiError(400, "User is not authorized to access")
    }

    // get the subTask title, description, status from the body
    const { subTaskTitle, subTaskDescription, subTaskCompletionStatus } = req.body

    // validate the projectId and taskId
    if (!taskId || !projectId) {
        throw new ApiError(400, "Project OR Task ID is not valid")
    }

    // validate the task and project id, it its existed or not
    const existedProject = await Project.findById({ projectId })

    if (!existedProject) {
        throw new ApiError(404, `${existedProject.projectName} not exists`)
    }

    const existedTask = await Task.findById({ taskId })

    if (!existedTask) {
        throw new ApiError(404, `${existedTask.title} not exists`)
    }

    // create the subTask in db
    const newSubTask = await Subtask.create({
        title: subTaskTitle,
        description: subTaskDescription,
        task: taskId,
        isCompleted: subTaskCompletionStatus,
        createdBy: userId
    })

    if (!newSubTask) {
        throw new ApiError(500, "Internal Server Error occurs while creating subtask")
    }

    // send success response to user
    res
        .status(201)
        .json(
            new ApiResponse(201, "SubTask Created Successfully", newSubTask)
        )

})

const updateSubTaskTitle = asyncHandler(async (req, res) => {
    // get the projectId, taskId, and subTaskId from the params
    const { projectId, taskId, subTaskId } = req.params

    // validate the projectId, taskId, and subTaskId
    if (![projectId, taskId, subTaskId].every(mongoose.Types.ObjectId.isValid)) {
        throw new ApiError(400, "projectId or taskId or SubtaskId is not valid")
    }

    if (!projectId) {
        throw new ApiError(404, "Project Not Found or Unauthorized request")
    }

    if (!taskId) {
        throw new ApiError(404, "Task Not Found or Unauthorized request")
    }

    if (!subTaskId) {
        throw new ApiError(404, "SubTask Not Found or Unauthorized request")
    }

    // get the subTask title from the body
    const { title } = req.body

    // check if the subTask exists or not
    const existedSubTask = await Subtask.findOne({
        _id: new mongoose.Types.ObjectId(subTaskId),
        task: new mongoose.Types.ObjectId(taskId)
    })
    if (!existedSubTask) {
        throw new ApiError(400, "SubTask not found")
    }

    // update the subTask title in db
    existedSubTask.title = title

    await existedSubTask.save()

    // send success response to user
    res
        .status(200)
        .json(
            new ApiResponse(200, "SubTask title updated successfully", existedSubTask)
        )
})

const updateSubTaskDescription = asyncHandler(async (req, res) => {
    // get the projectId, taskId, and subTaskId from the params
    const { projectId, taskId, subTaskId } = req.params

    // validate the projectId, taskId, and subTaskId
    if (![projectId, taskId, subTaskId].every(mongoose.Types.ObjectId.isValid)) {
        throw new ApiError(400, "projectId or taskId or SubtaskId is not valid")
    }

    if (!projectId) {
        throw new ApiError(404, "Project Not Found or Unauthorized request")
    }

    if (!taskId) {
        throw new ApiError(404, "Task Not Found or Unauthorized request")
    }

    if (!subTaskId) {
        throw new ApiError(404, "SubTask Not Found or Unauthorized request")
    }

    // get the subTask title from the body
    const { description } = req.body

    // check if the subTask exists or not
    const existedSubTask = await SubTask.findOne({
        _id: new mongoose.Types.ObjectId(subTaskId),
        task: new mongoose.Types.ObjectId(taskId)
    })
    if (!existedSubTask) {
        throw new ApiError(400, "SubTask not found")
    }

    // update the subTask title in db
    existedSubTask.description = description

    await existedSubTask.save()

    // send success response to user
    res
        .status(200)
        .json(
            new ApiResponse(200, "SubTask description updated successfully", existedSubTask)
        )
})

const subTaskIsCompleted = asyncHandler(async (req, res) => {
    // get the projectId, taskId, and subTaskId from the params
    const { projectId, taskId, subTaskId } = req.params

    // validate the projectId, taskId, and subTaskId
    if (![projectId, taskId, subTaskId].every(mongoose.Types.ObjectId.isValid)) {
        throw new ApiError(400, "projectId or taskId or SubtaskId is not valid")
    }

    if (!projectId) {
        throw new ApiError(404, "Project Not Found or Unauthorized request")
    }

    if (!taskId) {
        throw new ApiError(404, "Task Not Found or Unauthorized request")
    }

    if (!subTaskId) {
        throw new ApiError(404, "SubTask Not Found or Unauthorized request")
    }

    // get the subTask title from the body
    const { isCompleted } = req.body

    // check if the subTask exists or not
    const existedSubTask = await SubTask.findOne({
        _id: new mongoose.Types.ObjectId(subTaskId),
        task: new mongoose.Types.ObjectId(taskId)
    })
    if (!existedSubTask) {
        throw new ApiError(400, "SubTask not found")
    }

    // update the subTask title in db
    existedSubTask.isCompleted = isCompleted

    await existedSubTask.save()

    // send success response to user
    res
        .status(200)
        .json(
            new ApiResponse(200, "SubTask completion status updated successfully", existedSubTask)
        )
})

const getSubTasks = asyncHandler(async (req, res) => {
    // get the projectId and taskId from the params
    const { projectId, taskId } = req.params

    // validate the project and taskId via middleware or an external function
    if (!projectId) {
        throw new ApiError(404, "Project Not Found or Unauthorized request")
    }

    if (!taskId) {
        throw new ApiError(404, "Task Not Found or Unauthorized request")
    }

    // validate the task and project are existed or not
    const existedProject = await Project.findById({ projectId })

    if (!existedProject) {
        throw new ApiError(404, `${existedProject.projectName} not exists`)
    }

    const existedTask = await Task.findById({ taskId })

    if (!existedTask) {
        throw new ApiError(404, `${existedTask.title} not exists`)
    }

    // get all subtask with metadata includes task, title, description, createdBy, isCompleted, dueDate from the database
    const subTasks = await Subtask.aggregate(
        [
            {
                $match: {
                    task: new mongoose.Types.ObjectId(taskId),
                }
            },
            {
                $lookup: {
                    from: "users",
                    localField: "createdBy",
                    foreignField: "_id",
                    as: "subTaskCreatedBy"
                }
            },
            {
                $project: {
                    title: 1,
                    description: 1,
                    "existedTask.title": 1,
                    isCompleted: 1,
                    "subTaskCreatedBy.email": 1,
                    createdAt: 1
                }
            }
        ]
    )

    // send success response to user
    res
        .status(200)
        .json(
            new ApiResponse(200, "All SubTasks fetched successfully", subTasks)
        )
})

const getSubTaskById = asyncHandler(async (req, res) => {
    // get the projectId and taskId from the params
    const { projectId, taskId, subTaskId } = req.params

    // validate the project and taskId via middleware or an external function
    if (!projectId) {
        throw new ApiError(404, "Project Not Found or Unauthorized request")
    }

    if (!taskId) {
        throw new ApiError(404, "Task Not Found or Unauthorized request")
    }

    if (!subTaskId) {
        throw new ApiError(404, "SubTask Not Found or Unauthorized request")
    }

    // validate the task and project are existed or not
    const existedProject = await Project.findById(projectId)

    if (!existedProject) {
        throw new ApiError(404, `${existedProject.projectName} not exists`)
    }

    const existedTask = await Task.findById(taskId)

    if (!existedTask) {
        throw new ApiError(404, `${existedTask.title} not exists`)
    }

    const existedSubTask = await Task.findById(subTaskId)

    if (!existedSubTask) {
        throw new ApiError(404, `${existedSubTask.title} not exists`)
    }


    // get the subTaskById from the db, which includes metadata of title, desc, createdBy, updatedBy, duedate, task, isCompleted, labels, priority, status

    const subTask = await SubTask
        .findById(subTaskId)
        .populate({ path: "task", select: "title" })
        .populate({ path: "createdBy", select: "email avatar" })
        .exec()
        .then((subTask) => console.log(subTask))
        .catch((err) => console.log(err))

    //send success response to user
    res
        .status(200)
        .json(
            new ApiResponse(200, "Subtask fetched successfully", subTask)
        )
})

const deleteSubTask = asyncHandler(async (req, res) => {
    // get the projectId, taskId and subTaskId from the params
    const { projectId, taskId, subTaskId } = req.params

    // validate the projectId, taskId and subTaskId
    if (!projectId || projectId === undefined || projectId === null) {
        throw new ApiError(404, "Project Not Found or Unauthorized request")
    }

    if (!taskId) {
        throw new ApiError(404, "Task Not Found or Unauthorized request")
    }

    if (!subTaskId) {
        throw new ApiError(404, "SubTask Not Found or Unauthorized request")
    }

    // validate the task and subTask are existed or not

    const existedSubTask = await Task.findOne({
        task: mongoose.Types.ObjectId(taskId),
        subTask: mongoose.Types.ObjectId(subTaskId),
    })

    // check the user id is authorized to delete subTask

    // delete the subTask from the body
    await SubTask.findByIdAndDelete(existedSubTask._id)

    // send success response to user  
    res
        .status(200)
        .json(
            new ApiError(200, "SubTask deleted Successfully", null)
        )
})

const uploadAttachments = asyncHandler(async (req, res) => {
    // get the projectId, taskId from the params
    const { projectId, taskId } = req.params

    // get the userId from the req
    const userId = req.user._id

    // validate the params
    if (!projectId || projectId === undefined || projectId === null) {
        throw new ApiError(404, "Invalid Route")
    }

    if (!taskId) {
        throw new ApiError(404, "Invalid Route")
    }

    if (!userId) {
        throw new ApiError(404, "User Not Found or Unauthorized request")
    }

    // validate the task and project id, it its existed or not
    const existedProject = await Project.findById({ projectId })

    if (!existedProject) {
        throw new ApiError(404, `${existedProject.projectName} not exists`)
    }

    const existedTask = await Task.findById({ taskId })

    if (!existedTask) {
        throw new ApiError(404, `${existedTask.title} not exists`)
    }

    // get the files from the multer
    const files = req?.files || []
    console.log("files in uploadAttachments route ------ ", files, typeof files);

    // process all the files and upload it to cloudinary
    const attachments = Promise.all(
        files.map((file) => {
            const result = uploadOnCloudinary(file.path)
            return {
                url: result?.secure_url,
                name: file?.name,
                originalFileName: result?.original_filename,
                publicId: result?.public_id,
                mimetype: file?.mimetype,
                size: (file.size * 1024 * 1024)
            }
        })
    )

    console.log("uploaded files to cloudinary ---- ", attachments);

    // save attachments in db
    const taskAttachments = await Attachments.create({
        attachments: attachments,
        project: projectId,
        task: taskId,
        uploadedBy: userId,
    })

    // TODO: if possible implement queues to upload the files one by one reducing the load on the server and file compression algorithm too....

    // send success response to user
    res
        .status(200)
        .json(
            new ApiResponse(201, "Attachments uploaded successfully", taskAttachments)
        )
})

const getAttachmentsByTask = asyncHandler(async (req, res) => {
    // get the projectId, taskId from the params
    const { projectId, taskId } = req.params

    // get the userId from the req
    const userId = req.user._id

    // validate the params
    if (!projectId || projectId === undefined || projectId === null) {
        throw new ApiError(404, "Invalid Route")
    }

    if (!taskId) {
        throw new ApiError(404, "Invalid Route")
    }

    if (!userId) {
        throw new ApiError(404, "User Not Found or Unauthorized request")
    }

    // validate the task and project id, it its existed or not
    const existedProject = await Project.findById({ projectId })

    if (!existedProject) {
        throw new ApiError(404, `${existedProject.projectName} not exists`)
    }

    const existedTask = await Task.findById({ taskId })

    if (!existedTask) {
        throw new ApiError(404, `${existedTask.title} not exists`)
    }

    // get all the attachments from the db
    const taskAttachments = await Attachments.find({
        project: projectId,
        task: taskId
    })

    // send success response to user
    res
        .status(200)
        .json(
            new ApiResponse(201, "Task attachments fetched successfully", taskAttachments)
        )
})

const getAttachments = asyncHandler(async (req, res) => {
    // get the projectId, taskId from the params
    const { projectId, taskId } = req.params

    // get the userId from the req
    const userId = req.user._id

    // validate the params
    if (!projectId || projectId === undefined || projectId === null) {
        throw new ApiError(404, "Invalid Route")
    }

    if (!taskId) {
        throw new ApiError(404, "Invalid Route")
    }

    if (!userId) {
        throw new ApiError(404, "User Not Found or Unauthorized request")
    }

    // validate the task and project id, it its existed or not
    const existedProject = await Project.findById({ projectId })

    if (!existedProject) {
        throw new ApiError(404, `${existedProject.projectName} not exists`)
    }

    const existedTask = await Task.findById({ taskId })

    if (!existedTask) {
        throw new ApiError(404, `${existedTask.title} not exists`)
    }

    // get all the attachments from the db
    const allAttachments = await Attachments.aggregate(
        [
            {
                $match: {
                    project: projectId
                }
            },
            {
                $lookup: {
                    from: "projects",
                    localField: "project",
                    foreignField: "_id",
                    as: "projectDetails",
                }
            },
            {
                $lookup: {
                    from: "tasks",
                    localField: "task",
                    foreignField: "_id",
                    as: "taskDetails"
                }
            },
            {
                $lookup: {
                    from: "users",
                    localField: "uploadedBy",
                    foreignField: "_id",
                    as: "uploaderDetails"
                }
            },
            {
                $project: {
                    project: projectDetails.projectName,
                    task: taskDetails.title,
                    attachments: 1,
                    uploadedBy: {
                        fullname: 1,
                        avatar: 1,
                        createdAt: 1
                    }
                }
            }
        ]
    )

    // send success response to user
    res
        .status(200)
        .json(
            new ApiResponse(201, "All attachments fetched successfully", allAttachments)
        )
})

//^ TODO: Add an otp system to delete all the assets of the project for security measure
const deleteAllAttachments = asyncHandler(async (req, res) => {
    // get the projectId, taskId from the params
    const { projectId, taskId } = req.params

    // get the userId from the req
    const userId = req.user._id

    // validate the params
    if (!projectId || projectId === undefined || projectId === null) {
        throw new ApiError(404, "Invalid Route")
    }

    if (!taskId) {
        throw new ApiError(404, "Invalid Route")
    }

    if (!userId) {
        throw new ApiError(404, "User Not Found or Unauthorized request")
    }

    // validate the task and project id, it its existed or not
    const existedProject = await Project.findById({ projectId })

    if (!existedProject) {
        throw new ApiError(404, `${existedProject.projectName} not exists`)
    }

    const existedTask = await Task.findById({ taskId })

    if (!existedTask) {
        throw new ApiError(404, `${existedTask.title} not exists`)
    }

    // get the attachments from the user


    // delete it from the cloudinary
    // send success response to user
})

const deleteAllAttachmentsByTask = asyncHandler(async (req, res) => {
    // get the projectId, taskId from the params
    const { projectId, taskId } = req.params

    // get the userId from the req
    const userId = req.user._id

    // validate the params
    if (!projectId || projectId === undefined || projectId === null) {
        throw new ApiError(404, "Invalid Route")
    }

    if (!taskId) {
        throw new ApiError(404, "Invalid Route")
    }

    if (!userId) {
        throw new ApiError(404, "User Not Found or Unauthorized request")
    }

    // validate the task and project id, it its existed or not
    const existedProject = await Project.findById({ projectId })

    if (!existedProject) {
        throw new ApiError(404, `${existedProject.projectName} not exists`)
    }

    const existedTask = await Task.findById({ taskId })

    if (!existedTask) {
        throw new ApiError(404, `${existedTask.title} not exists`)
    }

    // fetch the attachments relates to the task
    const taskAttachments = await Attachments.find({
        task: taskId,
        project: projectId
    }).project({ "attachments.publicId": 1 })

    console.log("Task attachments public IDs --- ", taskAttachments);

    // delete the task attachments from the cloudinary
    const deleteTaskAttachments = deleteFromCloudinary(taskAttachments)
    console.log("deletedTaskAttachments ---- ", deleteTaskAttachments);

    // send success response to user
    res
        .status(200)
        .json(
            new ApiResponse(201, "Task attachments deleted successfully", deleteTaskAttachments)
        )

})

const deleteAttachmentByIds = asyncHandler(async (req, res) => {
    // get the projectId, taskId from the params
    const { projectId, taskId } = req.params

    // get the asset public ids from the body
    const { assetPublicIds } = req.body

    // get the userId from the req
    const userId = req.user._id

    // validate the params
    if (!projectId || projectId === undefined || projectId === null) {
        throw new ApiError(404, "Invalid Route")
    }

    if (!taskId) {
        throw new ApiError(404, "Invalid Route")
    }

    if (!userId) {
        throw new ApiError(404, "User Not Found or Unauthorized request")
    }

    // validate the taskId and projectId if its existed or not
    const existedProject = await Project.findById({ projectId: new mongoose.Types.ObjectId(projectId) })


    if (!existedProject) {
        throw new ApiError(404, `${existedProject.projectName} not exists`)
    }

    const existedTask = await Task.findById({ taskId })

    if (!existedTask) {
        throw new ApiError(404, `${existedTask.title} not exists`)
    }

    // delete attachments from the cloudinary
    const deleteAttachments = deleteFromCloudinary(assetPublicIds)

    console.log("Deleted Attachments from the cloudinary ----- ", deleteAllAttachments);

    // send success response to user
    res
        .status(200)
        .json(
            new ApiResponse(201, "Selected attachments deleted successfully", deleteAttachments)
        )
})

const deleteTask = asyncHandler(async (req, res) => {
    // get the projectId and task id from the params
    const { projectId, taskId } = req.params

    if (!projectId) {
        throw new ApiError(404, "Project Not Found or Unauthorized request")
    }

    if (!taskId) {
        throw new ApiError(404, "Task Not Found or Unauthorized request")
    }

    // check if the task already not exists
    const existedTask = await Task.findOne({
        project: new mongoose.Types.ObjectId(projectId),
        _id: new mongoose.Types.ObjectId(taskId)
    })

    if (!existedTask) {
        throw new ApiError(400, "Task not found")
    }

    // delete the task, allSubTasks, and all attachments
    await Task.findByIdAndDelete(existedTask._id)

    await Subtask.findByIdAndDelete({
        task: existedTask._id,
        project: new mongoose.Types.ObjectId(projectId),
    })

    await Attachments.findById({

    })

    // send success response to user
    res
        .status(200)
        .json(
            new ApiError(200, "Task deleted Successfully", null)
        )
})

export { createTask, getTasks, getTaskById, updateTaskTitle, updateTaskDescription, updateTaskStatus, updateTaskAssignee, createSubTask, updateSubTaskTitle, updateSubTaskDescription, subTaskIsCompleted, getSubTasks, getSubTaskById, deleteSubTask, uploadAttachments, getAttachmentsByTask, getAttachments, deleteAllAttachmentsByTask, deleteAllAttachments, deleteAttachmentByIds, deleteTask }

// user --> user uploads the file --> the file was saved into our server   (now that file can be previewed by the user to validate the file)

// if file was correct than user clicks save to save the file into cloudinary

// file was saved in cloud after user clicks save and after that uploadOnCloudinary controller was functioned

//* Attachments section teaches me ---> file compression before upload, queuing system, complex file handling and uploading, cron jobs, etc...