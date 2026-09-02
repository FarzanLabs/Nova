from __future__ import annotations

from dataclasses import dataclass

import httpx


@dataclass
class Profile:
    platform: str
    username: str
    url: str
    found: bool
    status: int | None = None
    name: str | None = None
    bio: str | None = None
    location: str | None = None
    website: str | None = None
    avatar: str | None = None


HEADERS = {
    "User-Agent": "Nova-OSINT/1.0"
}


def request_json(url: str):
    try:
        response = httpx.get(
            url,
            headers=HEADERS,
            timeout=10,
            follow_redirects=True,
        )

        if response.status_code == 200:
            return response.json(), 200

        return None, response.status_code

    except Exception:
        return None, None


def request_status(url: str):
    try:
        response = httpx.get(
            url,
            headers=HEADERS,
            timeout=8,
            follow_redirects=True,
        )

        return response.status_code

    except Exception:
        return None


def github(username: str) -> Profile:
    url = f"https://github.com/{username}"

    data, status = request_json(
        f"https://api.github.com/users/{username}"
    )

    if not data:
        return Profile(
            "GitHub",
            username,
            url,
            False,
            status,
        )

    return Profile(
        platform="GitHub",
        username=username,
        url=url,
        found=True,
        status=status,
        name=data.get("name"),
        bio=data.get("bio"),
        location=data.get("location"),
        website=data.get("blog"),
        avatar=data.get("avatar_url"),
    )


def reddit(username: str) -> Profile:
    url = f"https://www.reddit.com/user/{username}/"

    status = request_status(url)

    return Profile(
        platform="Reddit",
        username=username,
        url=url,
        found=status is not None and status < 400,
        status=status,
    )


def gitlab(username: str) -> Profile:
    url = f"https://gitlab.com/{username}"

    status = request_status(url)

    return Profile(
        platform="GitLab",
        username=username,
        url=url,
        found=status is not None and status < 400,
        status=status,
    )


def devto(username: str) -> Profile:
    url = f"https://dev.to/{username}"

    data, status = request_json(
        f"https://dev.to/api/users/by_username?url={username}"
    )

    if not data:
        return Profile(
            "Dev.to",
            username,
            url,
            False,
            status,
        )

    return Profile(
        platform="Dev.to",
        username=username,
        url=url,
        found=True,
        status=status,
        name=data.get("name"),
        website=data.get("website_url"),
        avatar=data.get("profile_image"),
    )


def pypi(username: str) -> Profile:
    url = f"https://pypi.org/user/{username}/"

    status = request_status(url)

    return Profile(
        platform="PyPI",
        username=username,
        url=url,
        found=status is not None and status < 400,
        status=status,
    )


def huggingface(username: str) -> Profile:
    url = f"https://huggingface.co/{username}"

    data, status = request_json(
        f"https://huggingface.co/api/users/{username}"
    )

    if not data:
        return Profile(
            "Hugging Face",
            username,
            url,
            False,
            status,
        )

    return Profile(
        platform="Hugging Face",
        username=username,
        url=url,
        found=True,
        status=status,
        name=data.get("fullname"),
        avatar=data.get("avatarUrl"),
    )


def search_username(username: str) -> list[Profile]:
    username = username.strip().lstrip("@")

    return [
        github(username),
        gitlab(username),
        reddit(username),
        devto(username),
        pypi(username),
        huggingface(username),
    ]
