
import json
import pandas as pd

activities = pd.read_csv(
    "dataset/system_activity.csv",
    dtype=str,
    keep_default_na=False
)

print("=" * 65)
print("RESOURCE IDENTITY LINK EVENTS")
print("=" * 65)

links = activities[
    activities["event_type"] == "LINK_RESOURCE_IDENTITY"
]

print("Total link events:", len(links))

for _, row in links.iterrows():
    print("\nActivity:", row["activity_id"])
    print("Time:", row["event_time"])
    print("Resource:", row["resource_id"])
    print("Source:", row["source_system"])
    print("Target:", row["target_system"])
    print("Result:", row["reported_result"])
    print("Details:", row["details"][:500])

print("\n" + "=" * 65)
print("RESTORE BACKUP EVENTS")
print("=" * 65)

restores = activities[
    activities["event_type"] == "RESTORE_BACKUP"
]

for _, row in restores.iterrows():
    print("\nActivity:", row["activity_id"])
    print("Time:", row["event_time"])
    print("Resource:", row["resource_id"])
    print("Source:", row["source_system"])
    print("Target:", row["target_system"])
    print("Result:", row["reported_result"])
    print("Details:", row["details"][:500])

print("\n" + "=" * 65)
print("SAMPLE ACTIVITY DETAILS")
print("=" * 65)

interesting_types = [
    "DELETE_RECORD",
    "SYNC_RECORD",
    "RETAIN_RECORD",
    "CHECK_DATA_FLOW",
    "BLOCK_RESTORE"
]

for event_type in interesting_types:
    subset = activities[
        activities["event_type"] == event_type
    ]

    if subset.empty:
        continue

    row = subset.iloc[0]

    print("\nEvent type:", event_type)
    print("Activity:", row["activity_id"])
    print("Resource:", row["resource_id"])
    print("Details:", row["details"][:500])

print("\nRESOURCE INSPECTION COMPLETE")
