
from pathlib import Path
import json
import pandas as pd


class EvidenceParser:
    def __init__(self, dataset_dir="dataset"):
        self.dataset = Path(dataset_dir)

        self.manifest = pd.read_csv(
            self.dataset / "evidence_files.csv",
            dtype=str,
            keep_default_na=False
        )

    def read_file(self, file_path):
        path = self.dataset / file_path
        extension = path.suffix.lower()

        if extension not in [".json", ".log", ".txt", ".sql"]:
            return None

        content = path.read_text(
            encoding="utf-8",
            errors="replace"
        )

        if extension == ".json":
            try:
                data = json.loads(content)
                content = json.dumps(
                    data,
                    ensure_ascii=False
                )
            except json.JSONDecodeError:
                pass

        return content

    def search_identity(self, identifiers, audit_at):
        matches = []

        cutoff = pd.to_datetime(audit_at, utc=True)

        terms = {
            str(value).strip().casefold()
            for value in identifiers
            if str(value).strip()
        }

        for _, row in self.manifest.iterrows():
            captured = pd.to_datetime(
                row["captured_at"],
                utc=True,
                errors="coerce"
            )

            if pd.isna(captured) or captured > cutoff:
                continue

            content = self.read_file(row["file_path"])

            if content is None:
                continue

            content_lower = content.casefold()

            found = sorted(
                term for term in terms
                if term in content_lower
            )

            if found:
                matches.append({
                    "evidence_id": row["file_id"],
                    "file_path": row["file_path"],
                    "matched_count": len(found),
                    "captured_at": row["captured_at"]
                })

        return matches


if __name__ == "__main__":
    from identity_resolver import IdentityResolver

    resolver = IdentityResolver()
    parser = EvidenceParser()

    requests = pd.read_csv(
        "dataset/deletion_requests.csv",
        dtype=str,
        keep_default_na=False
    )

    request = requests.iloc[0]

    identity = resolver.resolve_email(
        request["email"]
    )

    if identity is None:
        print("Identity not uniquely resolved")
        raise SystemExit(1)

    identifiers = set()

    identifiers.add(identity["user_id"])

    for key in [
        "emails",
        "names",
        "phones",
        "email_hashes"
    ]:
        identifiers.update(identity[key])

    matches = parser.search_identity(
        identifiers,
        request["audit_at"]
    )

    print("Case:", request["case_id"])
    print("User:", identity["user_id"])
    print("Audit time:", request["audit_at"])
    print("Matching evidence files:", len(matches))

    for match in matches:
        print(
            match["evidence_id"],
            "|",
            match["file_path"],
            "| identifiers:",
            match["matched_count"]
        )
