# tests/plugins/blackbox/test_cloud_storage_exposure.py
"""Tests for cloud storage exposure detection plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.cloud_storage_exposure import CloudStorageExposurePlugin
from vibee_hacker.core.models import Target, Severity


class TestCloudStorageExposure:
    @pytest.fixture
    def plugin(self):
        return CloudStorageExposurePlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/")

    @pytest.mark.asyncio
    async def test_s3_url_found_and_accessible(self, plugin, target, httpx_mock):
        """S3 URL found in page and bucket is publicly accessible."""
        # First request: fetch the main page containing S3 URL
        httpx_mock.add_response(
            url="https://example.com/",
            status_code=200,
            text='<html><body><img src="https://mybucket.s3.amazonaws.com/logo.png" /></body></html>',
        )
        # Second request: probe the S3 bucket root
        httpx_mock.add_response(
            url="https://mybucket.s3.amazonaws.com/",
            status_code=200,
            text='<?xml version="1.0"?><ListBucketResult><Name>mybucket</Name></ListBucketResult>',
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.CRITICAL
        assert results[0].rule_id == "cloud_storage_public"
        assert results[0].cwe_id == "CWE-284"

    @pytest.mark.asyncio
    async def test_no_cloud_urls_in_page(self, plugin, target, httpx_mock):
        """No cloud storage URLs in response produces no results."""
        httpx_mock.add_response(
            url="https://example.com/",
            status_code=200,
            text="<html><body>Normal page with no cloud storage URLs</body></html>",
        )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, target, httpx_mock):
        """Transport error fetching main page returns empty results."""
        httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []
