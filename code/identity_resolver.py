
from pathlib import Path
import pandas as pd


class IdentityResolver:
    def __init__(self, dataset_dir="dataset"):
        folder = Path(dataset_dir)

        self.users = pd.read_csv(
            folder / "user_identities.csv",
            dtype=str,
            keep_default_na=False
        )

        self.history = pd.read_csv(
            folder / "user_audit_log.csv",
            dtype=str,
            keep_default_na=False
        )

        self.email_to_users = {}
        self.user_identifiers = {}

        self.build_index()

    def add_email(self, email, user_id):
        email = email.strip().lower()

        if email:
            self.email_to_users.setdefault(
                email, set()
            ).add(user_id)

    def build_index(self):
        # Step 1: Current user information
        for _, row in self.users.iterrows():
            user_id = row["user_id"]

            self.user_identifiers[user_id] = {
                "user_id": user_id,
                "names": set(),
                "emails": set(),
                "phones": set(),
                "email_hashes": set()
            }

            self.add_identifier(
                user_id, "name", row["name"]
            )
            self.add_identifier(
                user_id, "email", row["email"]
            )
            self.add_identifier(
                user_id, "phone", row["phone"]
            )
            self.add_identifier(
                user_id, "email_hash", row["email_hash"]
            )

        # Step 2: Historical identity information
        for _, row in self.history.iterrows():
            user_id = row["user_id"]
            field = row["field_name"]

            if user_id not in self.user_identifiers:
                continue

            self.add_identifier(
                user_id, field, row["old_value"]
            )
            self.add_identifier(
                user_id, field, row["new_value"]
            )

    def add_identifier(self, user_id, field, value):
        value = value.strip()

        if not value:
            return

        field_map = {
            "name": "names",
            "email": "emails",
            "phone": "phones",
            "email_hash": "email_hashes"
        }

        if field not in field_map:
            return

        key = field_map[field]

        if field == "email":
            value = value.lower()
            self.add_email(value, user_id)

        self.user_identifiers[user_id][key].add(value)

    def resolve_email(self, email):
        email = email.strip().lower()
        matches = self.email_to_users.get(email, set())

        if len(matches) != 1:
            return None

        user_id = next(iter(matches))
        return self.user_identifiers[user_id]


if __name__ == "__main__":
    resolver = IdentityResolver()

    requests = pd.read_csv(
        "dataset/deletion_requests.csv",
        dtype=str,
        keep_default_na=False
    )

    resolved = 0
    unresolved = []

    for _, request in requests.iterrows():
        identity = resolver.resolve_email(
            request["email"]
        )

        if identity:
            resolved += 1
        else:
            unresolved.append(request["case_id"])

    print("Total requests:", len(requests))
    print("Resolved identities:", resolved)
    print("Unresolved or ambiguous:", len(unresolved))
    print("Unresolved case IDs:", unresolved[:20])

    print("\nExample identity:")
    first_email = requests.iloc[0]["email"]
    result = resolver.resolve_email(first_email)

    if result:
        print("User ID:", result["user_id"])
        print("Emails:", sorted(result["emails"]))
        print("Names:", sorted(result["names"]))
        print("Phones:", sorted(result["phones"]))
        print("Email hashes:", len(result["email_hashes"]))
    else:
        print("No unique identity found")
