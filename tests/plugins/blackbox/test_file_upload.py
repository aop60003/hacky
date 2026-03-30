# tests/plugins/blackbox/test_file_upload.py
import pytest
import httpx
from vibee_hacker.plugins.blackbox.file_upload import FileUploadPlugin
from vibee_hacker.core.models import Target, Severity


class TestFileUpload:
    @pytest.fixture
    def plugin(self):
        return FileUploadPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/upload")

    @pytest.mark.asyncio
    async def test_upload_form_detected(self, plugin, target, httpx_mock):
        # HTML with file input
        httpx_mock.add_response(
            url="https://example.com/upload",
            text='<html><form enctype="multipart/form-data" action="/upload">'
                 '<input type="file" name="file"></form></html>',
            status_code=200,
        )
        # Upload succeeds with a file path in the body
        httpx_mock.add_response(
            text='{"url":"/uploads/shell.php.jpg","status":"ok"}',
            status_code=200,
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.CRITICAL
        assert results[0].cwe_id == "CWE-434"
        assert results[0].rule_id == "file_upload_extension_bypass"

    @pytest.mark.asyncio
    async def test_no_upload_form(self, plugin, target, httpx_mock):
        # No file input in HTML — plugin should return empty
        httpx_mock.add_response(
            url="https://example.com/upload",
            text="<html><body>No forms here</body></html>",
            status_code=200,
        )
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_upload_rejected(self, plugin, target, httpx_mock):
        # HTML has upload form but server rejects with 403
        httpx_mock.add_response(
            url="https://example.com/upload",
            text='<html><form enctype="multipart/form-data"><input type="file" name="f"></form></html>',
            status_code=200,
        )
        httpx_mock.add_response(
            text="Forbidden",
            status_code=403,
        )
        results = await plugin.run(target)
        assert results == []
