from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx


HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; Nova-OSINT/1.0)"
}


@dataclass
class HTTPIntelligence:
    url: str
    final_url: str | None = None
    status_code: int | None = None
    server: str | None = None
    powered_by: str | None = None
    content_type: str | None = None
    content_length: str | None = None
    title: str | None = None
    technologies: list[str] | None = None
    security_headers: dict[str, str] | None = None
    redirects: list[str] | None = None


TECHNOLOGY_HEADERS = {
    "x-powered-by": "Technology",
    "x-generator": "Generator",
    "x-drupal-cache": "Drupal",
    "x-shopify-stage": "Shopify",
}


BODY_MARKERS = {
    "wp-content": "WordPress",
    "wp-includes": "WordPress",
    "woocommerce": "WooCommerce",
    "shopify": "Shopify",
    "cdn.shopify.com": "Shopify",
    "next/static": "Next.js",
    "__next_data__": "Next.js",
    "nuxt": "Nuxt",
    "react": "React",
    "vue": "Vue.js",
    "angular": "Angular",
    "laravel": "Laravel",
    "django": "Django",
    "flask": "Flask",
    "bootstrap": "Bootstrap",
    "jquery": "jQuery",
}


SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
]


def extract_title(html: str) -> str | None:

    match = re.search(
        r"<title[^>]*>(.*?)</title>",
        html,
        flags=re.I | re.S,
    )

    if not match:
        return None

    title = re.sub(
        r"\s+",
        " ",
        match.group(1),
    ).strip()

    return title[:300] if title else None


def detect_technologies(
    response: httpx.Response,
    body: str,
) -> list[str]:

    technologies = set()

    headers = {
        key.lower(): value
        for key, value in response.headers.items()
    }

    server = headers.get("server", "")

    if "nginx" in server.lower():
        technologies.add("Nginx")

    if "apache" in server.lower():
        technologies.add("Apache")

    if "cloudflare" in server.lower():
        technologies.add("Cloudflare")

    for header, technology in TECHNOLOGY_HEADERS.items():

        if header in headers:
            technologies.add(technology)

    body_lower = body.lower()

    for marker, technology in BODY_MARKERS.items():

        if marker.lower() in body_lower:
            technologies.add(technology)

    return sorted(technologies)


def scan_url(url: str) -> HTTPIntelligence:

    parsed = urlparse(url)

    if parsed.scheme not in {
        "http",
        "https",
    }:
        url = f"https://{url}"

    result = HTTPIntelligence(
        url=url,
        technologies=[],
        security_headers={},
        redirects=[],
    )

    try:

        with httpx.Client(
            headers=HEADERS,
            timeout=15,
            follow_redirects=True,
        ) as client:

            response = client.get(url)

            result.final_url = str(
                response.url
            )

            result.status_code = (
                response.status_code
            )

            result.server = response.headers.get(
                "server"
            )

            result.powered_by = response.headers.get(
                "x-powered-by"
            )

            result.content_type = response.headers.get(
                "content-type"
            )

            result.content_length = response.headers.get(
                "content-length"
            )

            result.title = extract_title(
                response.text
            )

            result.technologies = (
                detect_technologies(
                    response,
                    response.text,
                )
            )

            for header in SECURITY_HEADERS:

                value = response.headers.get(
                    header
                )

                if value:
                    result.security_headers[
                        header
                    ] = value

            for redirect in response.history:

                result.redirects.append(
                    str(redirect.url)
                )

            return result

    except Exception:
        return result