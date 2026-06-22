import json
import os
import boto3
import urllib.request
import urllib.error

dynamodb = boto3.client("dynamodb", region_name=os.environ["AWS_REGION"])
ssm = boto3.client("ssm", region_name=os.environ["AWS_REGION"])

_okta_url_cache = None
_sumo_url_cache = None


def get_okta_url():
    global _okta_url_cache
    if _okta_url_cache is None:
        resp = ssm.get_parameter(Name=os.environ["OKTA_WORKFLOWS_URL_PARAM"], WithDecryption=True)
        _okta_url_cache = resp["Parameter"]["Value"]
    return _okta_url_cache


def get_sumo_url():
    global _sumo_url_cache
    if _sumo_url_cache is None:
        resp = ssm.get_parameter(Name=os.environ["SUMO_LOGIC_URL_PARAM"], WithDecryption=True)
        _sumo_url_cache = resp["Parameter"]["Value"]
    return _sumo_url_cache


def get_machine_info(table_name, machine_id):
    """Fetch PrimaryUser and SerialNum from Rudolph SensorData."""
    try:
        resp = dynamodb.get_item(
            TableName=table_name,
            Key={
                "PK": {"S": f"Machine#{machine_id}"},
                "SK": {"S": "Current"},
            },
            ProjectionExpression="PrimaryUser, SerialNum",
        )
        item = resp.get("Item", {})
        return (
            item.get("PrimaryUser", {}).get("S", "unknown"),
            item.get("SerialNum", {}).get("S", "unknown"),
        )
    except Exception:
        return "unknown", "unknown"


def post_json(url, payload):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    urllib.request.urlopen(req, timeout=10)


def handler(event, context):
    table = os.environ["DYNAMODB_TABLE"]

    items = event.get("items", [])

    # --- Execution block events → Okta Workflows ---

    # Group BLOCK events by sha256 to deduplicate binaries in the same batch
    blocks = {}
    for item in items:
        if item.get("event_type") == "file_access":
            continue
        if not item.get("decision", "").startswith("BLOCK"):
            continue
        sha = item.get("file_sha256", "")
        if sha not in blocks:
            blocks[sha] = item
        # Count occurrences for block_count
        blocks[sha].setdefault("_count", 0)
        blocks[sha]["_count"] += 1

    if blocks:
        okta_url = get_okta_url()
        for sha, item in blocks.items():
            machine_id = item.get("machine_id", "")
            owner_email, serial_num = get_machine_info(table, machine_id)

            payload = {
                "file_path": item.get("file_path", ""),
                "file_name": item.get("file_name", ""),
                "file_sha256": sha,
                "signing_id": item.get("signing_id", ""),
                "team_id": item.get("team_id", ""),
                "cdhash": item.get("cdhash", ""),
                "bundle_name": item.get("file_bundle_name", ""),
                "bundle_version": item.get("file_bundle_version_string", ""),
                "decision": item.get("decision", ""),
                "machine_id": machine_id,
                "serial_num": serial_num,
                "owner_email": owner_email,
                "executing_user": item.get("executing_user", ""),
                "block_count": item["_count"],
                "source": event.get("source", ""),
            }

            try:
                post_json(okta_url, payload)
            except Exception as e:
                print(f"Failed to POST event for {sha} to Okta Workflows: {e}")

    # --- File access events → Sumo Logic ---

    faa_items = [i for i in items if i.get("event_type") == "file_access"]
    if faa_items:
        sumo_url = get_sumo_url()
        for item in faa_items:
            machine_id = item.get("machine_id", "")
            owner_email, serial_num = get_machine_info(table, machine_id)

            # First process in the chain is the offending process
            process_chain = item.get("processChain", [])
            proc = process_chain[0] if process_chain else {}

            payload = {
                "event_type": "file_access",
                "rule_name": item.get("ruleName", ""),
                "rule_version": item.get("ruleVersion", ""),
                "rule_id": item.get("ruleId", 0),
                "decision": item.get("decision", ""),
                "accessed_path": item.get("target", ""),
                "access_time": item.get("accessTime", 0),
                "process_path": proc.get("filePath", ""),
                "process_sha256": proc.get("fileSha256", ""),
                "process_cdhash": proc.get("cdhash", ""),
                "process_signing_id": proc.get("signingId", ""),
                "process_team_id": proc.get("teamId", ""),
                "process_pid": proc.get("pid", 0),
                "machine_id": machine_id,
                "serial_num": serial_num,
                "owner_email": owner_email,
                "source": event.get("source", ""),
            }

            try:
                post_json(sumo_url, payload)
            except Exception as e:
                print(f"Failed to POST FAA event to Sumo Logic: {e}")
