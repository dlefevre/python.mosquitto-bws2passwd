"""Bitwarden Secrets Manager client wrapper."""

import re

from bitwarden_sdk import BitwardenClient, DeviceType, client_settings_from_dict


def _build_client() -> BitwardenClient:
    return BitwardenClient(
        client_settings_from_dict(
            {
                "apiUrl": "https://api.bitwarden.com",
                "deviceType": DeviceType.SDK,
                "identityUrl": "https://identity.bitwarden.com",
                "userAgent": "bws2passwd",
            }
        )
    )


def fetch_secrets(access_token: str, organization_id: str, pattern: str) -> list[tuple[str, str]]:
    """
    Authenticate with Bitwarden SM and return ``(key, value)`` pairs for all
    secrets whose key matches *pattern*.

    :param access_token: Value of ``BWS_ACCESS_TOKEN``.
    :param organization_id: Value of ``BWS_ORGANIZATION_ID``.
    :param pattern: Regular expression matched against the secret key/name.
    :returns: List of ``(key, value)`` tuples in the order returned by the API.
    :raises re.error: If *pattern* is not a valid regular expression.
    :raises ValueError: If the organization ID cannot be extracted from the token.
    """
    compiled = re.compile(pattern)

    client = _build_client()
    client.auth().login_access_token(access_token)

    identifiers_response = client.secrets().list(organization_id)
    if identifiers_response.data is None:
        raise ValueError("Failed to fetch identifiers: no data in response")
    identifiers = identifiers_response.data.data

    matching_ids = [s.id for s in identifiers if compiled.search(s.key)]
    if not matching_ids:
        return []

    secrets_response = client.secrets().get_by_ids(matching_ids)
    if secrets_response.data is None:
        raise ValueError("Failed to fetch secrets: no data in response")
    return [(s.key.rsplit("/", 1)[-1], s.value) for s in secrets_response.data.data]
