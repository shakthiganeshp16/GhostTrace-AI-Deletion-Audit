
import json

from json_evidence_extractor import JSONEvidenceExtractor

extractor = JSONEvidenceExtractor()
records = extractor.extract_file("evidence_83")

search_terms = [
    "user_18",
    "ingrid.dahl@outlook.com"
]

print("TOTAL RECORDS:", len(records))

for record in records:
    text = json.dumps(
        record["data"],
        ensure_ascii=False
    ).casefold()

    found = [
        term for term in search_terms
        if term.casefold() in text
    ]

    if not found:
        continue

    print("\nEVIDENCE:", record["evidence_id"])
    print("SYSTEM:", record["system_id"])
    print("CATEGORY:", record["category"])
    print("RESOURCE:", record["resource_id"])
    print("MATCHED TERMS:", found)

    print("MATCHING FIELD PATHS:")

    def inspect(value, path="record"):
        if isinstance(value, dict):
            for key, item in value.items():
                inspect(item, f"{path}.{key}")

        elif isinstance(value, list):
            for index, item in enumerate(value):
                inspect(item, f"{path}[{index}]")

        elif isinstance(value, str):
            if any(
                term.casefold() in value.casefold()
                for term in search_terms
            ):
                print(path)

    inspect(record["data"])

print("\nDEBUG COMPLETE")
