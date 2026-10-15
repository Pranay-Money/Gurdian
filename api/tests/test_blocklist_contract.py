from datetime import datetime, timezone

from src.schemas import BlocklistDeltaResponse


def test_blocklist_delta_contract_uses_domain_hash_entries():
    timestamp = datetime.now(timezone.utc)
    response = BlocklistDeltaResponse(
        additions=[
            {
                "domain_hash": "abc123",
                "reason": "phishing",
                "expires_at": timestamp,
            }
        ],
        removals=["def456"],
        timestamp=timestamp,
    )

    assert response.model_dump()["additions"] == [
        {
            "domain_hash": "abc123",
            "reason": "phishing",
            "expires_at": timestamp,
        }
    ]
