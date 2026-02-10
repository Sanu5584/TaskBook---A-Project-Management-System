export const TaskStatusEnum = {
    TODO: "todo",
    IN_PROGRESS: "in_progress",
    DONE: "done"
}

export const AvailableTaskStatus = Object.values(TaskStatusEnum)

export const avatarMimetype = ["image/jpeg", "image/png", "image/avif", "image/webp"]

export const ProjectStatusEnum = {
    PENDING: "pending",
    IN_PROGRESS: "in_progress",
    COMPLETED: "completed"
}

export const AvailableProjectStatus = Object.values(ProjectStatusEnum)

export const userRolesEnum = {
    Admin: "Admin",
    SubAdmin: "SubAdmin",
    ProjectAdmin: "ProjectAdmin",
    Member: "Member"
}

export const userPermissions = {
    Admin: [
        //* for projects
        "create:project",
        "delete:project",
        "edit:project",
        "view:project",
        "addMember:project",
        "updateMember:project",
        "removeMember:project",

        //* for tasks
        "create:task",
        "delete:task",
        "edit:task",
        "view:task",
        "assignMembers:task",
        "removeAssignedMembers:task",
        "updateAssignedMembers:task",

        //* for subTasks
        "create:subTask",
        "delete:subTask",
        "view:subTask",
        "edit:subTask",

        //* for attachments
        "upload:attachments",
        "delete:attachments",
        "view:attachments"
    ],
    // SubAdmin: [
    //     //* for projects
    //     "create:project",
    //     "edit:project",
    //     "view:project",
    //     "addMember:project",
    //     "updateMember:project",
    //     "removeMember:project",

    //     //* for tasks
    //     "edit:task",
    //     "view:task",

    //     //* for subTasks
    //     "view:subTask",
    //     "edit:subTask"
    // ],
    ProjectAdmin: [
        //* for projects
        "edit:project",
        "view:project",
        "addMember:project",
        "updateMember:project",
        "removeMember:project",

        //* for tasks
        "create:task",
        "delete:task",
        "edit:task",
        "view:task",
        "assignMembers:task",
        "removeAssignedMembers:task",
        "updateAssignedMembers:task",

        //* for subTasks
        "create:subTask",
        "delete:subTask",
        "view:subTask",
        "edit:subTask",

        //* for attachments
        "upload:attachments",
        "delete:attachments",
        "view:attachments"
    ],
    Member: [
        //* for projects
        "view:project",

        //* for tasks
        "create:task",
        "delete:task",
        "edit:task",
        "view:task",
        "assignMembers:task",
        "removeAssignedMembers:task",
        "updateAssignedMembers:task",

        //* for subTasks
        "create:subTask",
        "delete:subTask",
        "view:subTask",
        "edit:subTask",

        //* for attachments
        "upload:attachments",
        "view:attachments"
    ],
    // WorkspaceMemberReadOnly: [
    //     //* for projects
    //     "view:project"
    // ]
}

export const AvailableUserRolesPermission = Object.keys(userPermissions)