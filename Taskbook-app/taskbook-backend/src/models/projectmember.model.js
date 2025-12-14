import mongoose, { Schema } from "mongoose";

import { AvailableUserRolesPermission, userRolesEnum } from "../utils/constants.utils.js";

const projectMember = new Schema(
    {
        user: {
            type: Schema.Types.ObjectId,
            ref: "User",
            required: true
        },
        project: {
            type: Schema.Types.ObjectId,
            ref: "Project",
            required: true
        },
        role: {
            type: String,
            enum: AvailableUserRolesPermission,
            default: userRolesEnum.Member,
        }
    },
    {
        timestamps: true
    }
)

const ProjectMember = mongoose.model("ProjectMember", projectMember)

export default ProjectMember