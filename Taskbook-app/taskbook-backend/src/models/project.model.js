import mongoose, { Schema } from "mongoose";
import { AvailableProjectStatus, ProjectStatusEnum } from "../utils/constants.utils.js";

const project = new Schema(
    {
        projectName: {
            type: String,
            required: true,
            trim: true
        },
        projectDescription: {
            type: String,
            required: true
        },
        uniqueProjectIdentifier: {
            type: String,
            required: true,
            unique: true,
            trim: true
        },
        projectDueDate: {
            type: Date,
        },
        createdBy: {
            type: Schema.Types.ObjectId,
            ref: "User",
            required: true
        },
        // projectRole: {
        //     type: Array,
        //     trim: true
        // },
        status: {
            type: String,
            trim: true,
            enum: AvailableProjectStatus,
            default: ProjectStatusEnum.PENDING
        }
    },
    {
        timestamps: true
    }
)

const Project = mongoose.model("Project", project)

export default Project