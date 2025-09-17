import boto3
import json
from botocore.exceptions import ClientError

iam = boto3.client("iam")

PERMISSIVE_ACTIONS = [
    "iam:addusertogroup",
    "iam:attachgrouppolicy",
    "iam:attachrolepolicy",
    "iam:attachuserpolicy",
    "iam:createaccesskey",
    "iam:createpolicyversion",
    "iam:deleterolepermissionsboundary",
    "iam:deleteuserpolicy",
    "iam:createloginprofile",
    "iam:passrole",
    "autoscaling:createautoscalinggroup",
    "autoscaling:updateautoscalinggroup",
    "autoscaling:createlaunchconfiguration",
    "ec2:createlaunchtemplate",
    "bedrock-agentcore:createcodeinterpreter",
    "bedrock-agentcore:invokecodeinterpreter",
    "cloudformation:createstack",
    "codestar:createproject",
    "datapipeline:activatepipeline",
    "datapipeline:createpipeline",
    "datapipeline:putpipelinedefinition",
    "ec2:runinstances",
    "ec2:deleteresourcepolicy",
    "ecs:runtask",
    "glue:updatejob",
    "lambda:addpermission",
    "lambda:createfunction",
    "lambda:invokefunction",
    "iam:putrolepolicy",
    "iam:setdefaultpolicyversion",
    "lambda:updatefunctionconfiguration",
    "ecs:starttask",
    "ecs:registercontainerinstance",
    "ecs:deregistercontainerinstance"
]

def check_policy_for_permissive_actions(policy_doc):
    """Check if a policy document grants any PERMISSIVE_ACTIONS or wildcards."""
    findings = []
    statements = policy_doc.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]

    for stmt in statements:
        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]

        actions_normalized = [a.lower() for a in actions]
        resources_normalized = [str(r).lower() for r in resources]

        # Detect wildcards
        if "*" in actions_normalized or any(":" in a and a.endswith(":*") for a in actions_normalized):
            findings.append({"Action": "WildcardDetected", "Resource": resources_normalized})

        # Detect specific permissive actions
        risky = [perm for perm in PERMISSIVE_ACTIONS if perm in actions_normalized]
        for r in risky:
            findings.append({"Action": r, "Resource": resources_normalized})

    return findings

def get_policy_document(policy_arn):
    try:
        policy = iam.get_policy(PolicyArn=policy_arn)
        version_id = policy["Policy"]["DefaultVersionId"]
        version = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
        return version["PolicyVersion"]["Document"]
    except ClientError as e:
        print(f" Could not fetch policy {policy_arn}: {e}")
        return {}

def paginate_list(method, key):
    paginator = iam.get_paginator(method)
    for page in paginator.paginate():
        for item in page[key]:
            yield item

def detect_permissive_iam_access():
    findings = []

    # --- Users ---
    try:
        for user in paginate_list("list_users", "Users"):
            user_name = user["UserName"]

            # Attached policies
            attached = iam.list_attached_user_policies(UserName=user_name)["AttachedPolicies"]
            for pol in attached:
                doc = get_policy_document(pol["PolicyArn"])
                detected = check_policy_for_permissive_actions(doc)
                if detected:
                    findings.append({"Entity": "User", "Name": user_name, "Policy": pol["PolicyName"], "Findings": detected})

            # Inline policies
            inline = iam.list_user_policies(UserName=user_name)["PolicyNames"]
            for pol in inline:
                doc = iam.get_user_policy(UserName=user_name, PolicyName=pol)["PolicyDocument"]
                detected = check_policy_for_permissive_actions(doc)
                if detected:
                    findings.append({"Entity": "User", "Name": user_name, "Policy": pol, "Findings": detected})
    except ClientError as e:
        print(f" Error checking users: {e}")

    # --- Roles ---
    try:
        for role in paginate_list("list_roles", "Roles"):
            role_name = role["RoleName"]

            attached = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
            for pol in attached:
                doc = get_policy_document(pol["PolicyArn"])
                detected = check_policy_for_permissive_actions(doc)
                if detected:
                    findings.append({"Entity": "Role", "Name": role_name, "Policy": pol["PolicyName"], "Findings": detected})

            inline = iam.list_role_policies(RoleName=role_name)["PolicyNames"]
            for pol in inline:
                doc = iam.get_role_policy(RoleName=role_name, PolicyName=pol)["PolicyDocument"]
                detected = check_policy_for_permissive_actions(doc)
                if detected:
                    findings.append({"Entity": "Role", "Name": role_name, "Policy": pol, "Findings": detected})
    except ClientError as e:
        print(f" Error checking roles: {e}")

    # --- Groups ---
    try:
        for group in paginate_list("list_groups", "Groups"):
            group_name = group["GroupName"]

            attached = iam.list_attached_group_policies(GroupName=group_name)["AttachedPolicies"]
            for pol in attached:
                doc = get_policy_document(pol["PolicyArn"])
                detected = check_policy_for_permissive_actions(doc)
                if detected:
                    findings.append({"Entity": "Group", "Name": group_name, "Policy": pol["PolicyName"], "Findings": detected})

            inline = iam.list_group_policies(GroupName=group_name)["PolicyNames"]
            for pol in inline:
                doc = iam.get_group_policy(GroupName=group_name, PolicyName=pol)["PolicyDocument"]
                detected = check_policy_for_permissive_actions(doc)
                if detected:
                    findings.append({"Entity": "Group", "Name": group_name, "Policy": pol, "Findings": detected})
    except ClientError as e:
        print(f" Error checking groups: {e}")

    # --- Results ---
    if findings:
        print("\n Found Permissive Policies:\n")
        print(json.dumps(findings, indent=2))
        # Save to file for audit
        with open("permissive_iam_findings.json", "w") as f:
            json.dump(findings, f, indent=2)
        print("\n Findings saved to permissive_iam_findings.json")
    else:
        print(" No permissive policies found.")


if __name__ == "__main__":
    detect_permissive_iam_access()
