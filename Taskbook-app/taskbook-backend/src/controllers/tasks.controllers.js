import { asyncHandler } from "../utils/async-handler.utils.js";
import { ApiError } from "../utils/api-error.utils.js"
import Task from "../models/task.model.js"
import Project from "../models/project.model.js"
import SubTask from "../models/subtask.model.js"
import { uploadOnCloudinary } from "../configs/cloudinary.config.js";
import mongoose from "mongoose";
import { ApiResponse } from "../utils/api-response.utils.js";
import { AvailableTaskStatus } from "../utils/constants.utils.js";

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

    // check that the status's value is presents in the taskStatusEnum


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

    console.log(files);

    //  process all files and upload to cloudinary
    const attachments = await Promise.all(
        files.map(async (file) => {
            const result = await uploadOnCloudinary(file.path)
            console.log("result : ", result);
            return {
                url: result?.secure_url,
                name: file.name,
                mimetype: file.mimetype,
                size: (file.size * 1024 * 1024),
            }
        })
    )

    console.log("Attachments : ", attachments);

    createTask.attachments = attachments


    // save the db
    await createTask.save()

    // send the success response to user

    return res
        .status(201)
        .json(201, `${title} Created Successfully`, createTask)
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
                $addFields: {
                    attachmentsCount: {
                        $size: {
                            $ifNull: ["$attachments", []]
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
                //lookup for assignedTo users to get that user's names and avatars
                $lookup: {
                    from: "users",
                    localField: "assignedTo",
                    foreignField: "_id",
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
                    project: {
                        _id: 1,
                        projectName: 1,
                    }
                }
            }
        ]
    )

    if (!allTasks) {
        throw new ApiError(404, "No tasks created yet")
    }

    res
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
                    _id: taskId
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
                $lookup: {
                    from: "users",
                    localField: "assignedBy",
                    foreignField: "_id",
                    as: "createdBy"
                }
            },
            {
                $lookup: {
                    from: "users",
                    localField: "assignedTo",
                    foreignField: "_id",
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

const updateTaskName = asyncHandler(async (req, res) => {
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

const updateTaskAssignees = asyncHandler(async (req, res) => {
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

    // check if assignedTo value is from the projectMember's enum only // ! implement this

    // update the assignee
    existedTask.assignedTo = assignedTo
    existedTask.save()

    // send success response to user
    res
        .status(200)
        .json(200, "Task assignee updated successfully", existedTask)
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
    const newSubTask = await SubTask.create({
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
    const existedSubTask = await SubTask.findOne({
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
    const subTasks = await SubTask.aggregate(
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

    // delete the task
    await Task.findByIdAndDelete(existedTask._id)

    // send success response to user
    res
        .status(200)
        .json(
            new ApiError(200, "Task deleted Successfully", null)
        )
})

export { createTask, getTasks, getTaskById, updateTaskName, updateTaskDescription, updateTaskStatus, updateTaskAssignees, createSubTask, updateSubTaskTitle, updateSubTaskDescription, subTaskIsCompleted, getSubTasks, getSubTaskById, deleteSubTask, deleteTask }