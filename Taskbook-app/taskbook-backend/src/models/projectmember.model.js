import mongoose, { Schema } from "mongoose";

import { UserRolesEnum, AvailableUserRoles } from "../utils/constants.utils.js";

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
            required: true,
            enum: AvailableUserRoles,
            default: UserRolesEnum.MEMBER
        }
    },
    {
        timestamps: true
    }
)

const ProjectMember = mongoose.model("ProjectMember", projectMember)

export default ProjectMember