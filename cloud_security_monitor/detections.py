"""Simple CloudTrail event detections for a lab security monitor."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


REVIEW_FLAG = "Review"

FAILED_AUTH_ERROR_CODES = {
    "AccessDenied",
    "AccessDeniedException",
    "Client.UnauthorizedOperation",
    "InvalidClientTokenId",
    "InvalidUserID.NotFound",
    "LoginFailure",
    "SignatureDoesNotMatch",
    "UnauthorizedOperation",
}

IAM_USER_CREATION_EVENTS = {
    "CreateUser",
}

IAM_POLICY_CHANGE_EVENTS = {
    "AddUserToGroup",
    "AttachGroupPolicy",
    "AttachRolePolicy",
    "AttachUserPolicy",
    "CreateGroup",
    "CreatePolicy",
    "CreatePolicyVersion",
    "DeleteGroupPolicy",
    "DeletePolicy",
    "DeletePolicyVersion",
    "DetachGroupPolicy",
    "DetachRolePolicy",
    "DetachUserPolicy",
    "PutGroupPolicy",
    "PutRolePolicy",
    "PutUserPolicy",
    "SetDefaultPolicyVersion",
}

SECURITY_GROUP_CHANGE_EVENTS = {
    "AuthorizeSecurityGroupEgress",
    "AuthorizeSecurityGroupIngress",
    "CreateSecurityGroup",
    "DeleteSecurityGroup",
    "RevokeSecurityGroupEgress",
    "RevokeSecurityGroupIngress",
    "UpdateSecurityGroupRuleDescriptionsEgress",
    "UpdateSecurityGroupRuleDescriptionsIngress",
}

ACCESS_KEY_CHANGE_EVENTS = {
    "CreateAccessKey",
    "DeleteAccessKey",
    "UpdateAccessKey",
}

ADMINISTRATIVE_ACTION_EVENTS = {
    "CreateTrail",
    "DeleteTrail",
    "StartLogging",
    "StopLogging",
    "UpdateTrail",
}


@dataclass(frozen=True)
class Finding:
    """A security-related event that should be reviewed."""

    time: str
    event: str
    user: str
    flag: str
    source: str
    event_name: str
    resource: str
    reason: str


def detect_event(record: dict[str, Any]) -> Finding | None:
    """Return a finding for a CloudTrail record, or None if it is not monitored."""

    event_name = str(record.get("eventName", "Unknown"))
    event_source = str(record.get("eventSource", "Unknown"))
    event_time = str(record.get("eventTime", "Unknown"))
    user = extract_user(record)
    resource = extract_resource(record)

    if is_failed_authentication(record):
        return Finding(
            time=event_time,
            event="Login or API failure",
            user=user,
            flag=REVIEW_FLAG,
            source=event_source,
            event_name=event_name,
            resource=resource,
            reason="A console sign-in or API request failed with an authentication or authorization error.",
        )

    if event_source == "iam.amazonaws.com" and event_name in IAM_USER_CREATION_EVENTS:
        return Finding(
            time=event_time,
            event="IAM user created",
            user=user,
            flag=REVIEW_FLAG,
            source=event_source,
            event_name=event_name,
            resource=resource,
            reason="A new IAM user was created and should be verified in a lab account.",
        )

    if event_source == "iam.amazonaws.com" and event_name in IAM_POLICY_CHANGE_EVENTS:
        return Finding(
            time=event_time,
            event="IAM permission changed",
            user=user,
            flag=REVIEW_FLAG,
            source=event_source,
            event_name=event_name,
            resource=resource,
            reason="An IAM group, role, user policy, or managed policy was changed.",
        )

    if event_source == "ec2.amazonaws.com" and event_name in SECURITY_GROUP_CHANGE_EVENTS:
        return Finding(
            time=event_time,
            event="Security group changed",
            user=user,
            flag=REVIEW_FLAG,
            source=event_source,
            event_name=event_name,
            resource=resource,
            reason="A security group or security group rule was created, deleted, or modified.",
        )

    if event_source == "iam.amazonaws.com" and event_name in ACCESS_KEY_CHANGE_EVENTS:
        return Finding(
            time=event_time,
            event="Access key changed",
            user=user,
            flag=REVIEW_FLAG,
            source=event_source,
            event_name=event_name,
            resource=resource,
            reason="An IAM access key was created, deleted, or updated.",
        )

    if event_source == "cloudtrail.amazonaws.com" and event_name in ADMINISTRATIVE_ACTION_EVENTS:
        return Finding(
            time=event_time,
            event="CloudTrail admin action",
            user=user,
            flag=REVIEW_FLAG,
            source=event_source,
            event_name=event_name,
            resource=resource,
            reason="A CloudTrail configuration or logging action was performed.",
        )

    return None


def is_failed_authentication(record: dict[str, Any]) -> bool:
    """Detect failed console logins and API calls denied by AWS."""

    event_name = str(record.get("eventName", ""))
    response_elements = record.get("responseElements") or {}
    error_code = str(record.get("errorCode", ""))

    if event_name == "ConsoleLogin" and response_elements.get("ConsoleLogin") == "Failure":
        return True

    return error_code in FAILED_AUTH_ERROR_CODES or "AccessDenied" in error_code


def extract_user(record: dict[str, Any]) -> str:
    """Extract a readable actor from the CloudTrail userIdentity object."""

    identity = record.get("userIdentity") or {}
    user_name = identity.get("userName")
    arn = identity.get("arn")
    principal_id = identity.get("principalId")

    if user_name:
        return str(user_name)
    if arn:
        return str(arn).split("/")[-1]
    if principal_id:
        return str(principal_id)
    return "Unknown"


def extract_resource(record: dict[str, Any]) -> str:
    """Extract the first useful resource name from a CloudTrail record."""

    resources = record.get("resources") or []
    if resources:
        first = resources[0]
        if isinstance(first, dict):
            return str(first.get("resourceName") or first.get("ARN") or "Unknown")

    request_parameters = record.get("requestParameters") or {}
    for key in (
        "userName",
        "policyName",
        "policyArn",
        "groupId",
        "groupName",
        "roleName",
        "trailName",
        "accessKeyId",
    ):
        value = request_parameters.get(key)
        if value:
            return str(value)

    return "Unknown"

