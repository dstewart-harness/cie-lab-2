# OPA Policy for controlling who can create new pipelines in the Platform Engineering project.
package pipeline_forbidden

# List of user groups that are NOT allowed to create new pipelines
disallowed_usergroups = ["SalesEngineers", "UserGroupB"]

# Deny access if the user's group is in the disallowed list
deny[sprintf("You are a part of a usergroup who is not allowed to create new pipelines in this project: '%s'. Please contact XXX for access", [disallowed_usergroup])] {
    userGroups = input.metadata.userGroups[_]     # Get each user group in the metadata
    userGroupId = userGroups.identifier   # Extract the identifier of the user group
    disallowed_usergroup = disallowed_usergroups[_] # Get each disallowed group
    contains(userGroups.identifier, disallowed_usergroup) # Check if the user's group is in the disallowed list
}