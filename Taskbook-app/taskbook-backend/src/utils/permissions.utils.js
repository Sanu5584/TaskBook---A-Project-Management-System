import { ApiError } from "./api-error.utils.js"
import ProjectMember from "../models/projectmember.model.js"

const userRoles = {
    Admin: [
        //* for projects
        "create:project",
        "delete:project",
        "edit:project",
        "view:project",
        "addMember:project",
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
        "edit:subTask"
    ],
    SubAdmin: [
        //* for projects
        "create:project",
        "edit:project",
        "view:project",
        "addMember:project",
        "removeMember:project",

        //* for tasks
        "edit:task",
        "view:task",

        //* for subTasks
        "view:subTask",
        "edit:subTask"
    ],
    ProjectMember: [
        //* for projects
        "edit:project",
        "view:project",
        "addMember:project",
        "removeMember:project",
        "viewMember:project",

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
        "edit:subTask"
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
        "edit:subTask"
    ],
}

const AvailableUserRoles = Object.keys(userRoles)

// const permissionsList = Object.values(userRoles).flat()

const validatePermission = async function (permission, userId, projectId) {
    try {
        const projectmember = await ProjectMember.findOne({
            user: userId,
            project: projectId
        })

        const userRole = projectmember?.role

        if (!AvailableUserRoles.includes(userRole)) {
            throw new ApiError(401, "Unauthorized Request")
        }

        const incomingPermission = userRoles[userRole]
        const hasPermission = incomingPermission.includes(permission)

        if (!hasPermission) {
            throw new ApiError(401, "Unauthorized Access")
        }

        return hasPermission

    } catch (error) {
        throw new ApiError(500, "INTERNAL SERVER ERROR: while validate the role")
    }
}

export { userRoles, AvailableUserRoles, validatePermission }

/**
         * ********* @Permissions Architecture **********
         * 
         * * Step 1
         * ? - There exists an array of different actions as per the role
         * ? - if a user create the project, then they are the project admin
         * 
         * ~ Implement it in the project
         * ^ make a json of all actions as per the the role(ADMIN, PROJECT_ADMIN, MEMBER)
         * ^
         * ^    - ADMIN - project(can_delete, can_create, can_view, can_update, add_member, delete_member, edit_member), task(can_create, can_delete, can_view, can_update, can_assign_members, can_remove_members), subTasks(can_delete, can_create, can_view, can_update)
         * ^
         * ^    - PROJECT_ADMIN - project(can_view, can_update, add_member, delete_member, edit_member), task(can_create, can_delete, can_view, can_update, can_assign_members, can_remove_members), subTasks(can_delete, can_create, can_view, can_update, can_create)
         * ^
         * ^    - MEMBER - project(can_view), task(can_create, can_delete, can_view, can_update, can_assign_members, can_remove_members), subTasks(can_delete, can_create, can_view, can_update, can_create)
         * ^ 
         * ^
         * * Step 2
         * ? - There is a function which validates the roles as per the incoming roles and matching the data from the defined array
         * 
         * ~ Implement it in the project
         * ^ Main workings of this function - role verfification via DB, Relation mapping
         * 
         * ^  ---- get the access permit action of features, userId, projectId from the middleware
         * ^  ---- check the user-project mapping
         * ^  ---- find the user based on the incoming data
         * ^  ---- validate the permit features 
         * ^  ---- if user found and validated then get the role of the user
         * ^  ---- check the permission and userRole mapping
         * ^  ---- if role is validated to perform the predefined action of the route, then return the user role and user data and sends that the user is validated to perform the action
         * 
         * 
         * * Step 3
         * ? - A middleware checks the incoming role and validate it and pass it to the step 2 to do further process and sends final response to user
         *  
         * ~ Implement it in the project
         * ^ - get the access permit action of features from the middleware
         * ^ - get the user id from the req object
         * ^ - validate the userId
         * ^ - get the projectId from the params
         * ^ - validate the projectId
         * ^ - run accessPermit function to validate the permission was relates to the user's and it's role
         * ^ - if not accessable then throw error
         * ^ - else run next() function
         * 
         * 
         * * Permissions flow
         * ? - A user of role 'project_admin' of project1 
         * ?   -> tried to access the project admin dashboard of project2
         * ?     -> then the request goes to auth.middleware to verify that user is authenticated or not
         * ?        -> if validated, then request goes to the step 3, in which middleware passes the request to the step 2
         * ?            -> then step 2 verify the role's access permissions, by verifying the actions   which user want to do was listed in the array of defined actions in Step 1
         * ?                -> then step 2 passes the response that the action, the user desired to do was not mentioned for that role
         * ?                    -> then the step 3, middleware sends the response that the user is unauthorized coz you are not a project_admin of the particular poject and is a forbidden request
         * 
         * # same flow goes if the user is validated than the further actions are goes on
         * 
         * TODO: Implement different authorization module for a internal project access control including custom roles for the specific project 
         * 
        */