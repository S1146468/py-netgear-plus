"""Unit tests for the py_netgear_plus __init__ module."""

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import Mock, call, patch

import pytest
import requests
import requests.cookies
from py_netgear_plus import (
    DEFAULT_PAGE,
    NetgearSwitchConnector,
    _from_bytes_to_megabytes,
)
from py_netgear_plus.fetcher import (
    URL_REQUEST_TIMEOUT,
    BaseResponse,
    PageFetcher,
    PageFetcherConnectionError,
    PageNotLoadedError,
    status_code_no_response,
    status_code_unauthorized,
)
from py_netgear_plus.models import (
    GS105PE,
    GS110EMX,
    GS305E,
    GS308E,
    GS308EP,
    GS308EPP,
    GS316EPP,
    GSS108E,
    JGS516PE,
    MS305E,
    MS308E,
    XS512EM,
    AutodetectedSwitchModel,
    GS105Ev2,
    GS108Ev3,
    GS108Ev4,
    GS108PEv3,
    GS308Ev4,
    JGS524Ev2,
)
from py_netgear_plus.netgear_crypt import hex_hmac_md5, merge_hash

if TYPE_CHECKING:
    from http.cookiejar import Cookie

# List of models with saved pages, extracted rand values and crypted passwords
MODEL_PARAMETERS = [
    (GS105Ev2, "897006492", "6e5b60b4082b2ac23103ec2e7caf0284", "<html></html>"),
    (GS105PE, "1578591883", "99915f464feee3be4193edd6dcc6b9b3", "<html></html>"),
    (GS108Ev3, "1763184457", "c2c905d5d99f592106a378bf709b737a", "<html></html>"),
    (GS108PEv3, "1735414426", "2038fc386c5e77ded19b31d7aa14a443", "<html></html>"),
    (
        GS110EMX,
        "2055460636",
        "3e51baecfd84e4c0010662d6d92a1253",
        '<html><input name="Gambit" value="cookie_value"></html>',
    ),
    (GS108Ev4, "1798387901", "0b9b21bb5c28b73e300cfb526d468bd9", "<html></html>"),
    (GS305E, "1018767543", "c01909066125ac45d275af0a6cd09b5e", "<html></html>"),
    (GS308E, "2102219470", "e8e0a9820f683fe8e64da0014a49902c", "<html></html>"),
    (GS308EP, "990464497", "43001294a37a3f2e1f919b64072a1a32", "<html></html>"),
    (GS308EPP, "1425622205", "e65ad5ee60718843afafeaa03bd1ec49", "<html></html>"),
    (
        GS316EPP,
        "1127757600",
        "3c630eb52109743e94ef671e137b3de0",
        '<html><input name="Gambit" value="cookie_value"></html>',
    ),
    (
        GS308Ev4,
        "1467252539",
        "5f01444681a83b9a39c6e9e1ea2a91db",
        "<html></html>",
    ),
    (
        JGS516PE,
        None,
        "26fe7cce1e480dd05e7f76155579d3ed",
        "<html></html>",
    ),
    (
        JGS524Ev2,
        None,
        "26fe7cce1e480dd05e7f76155579d3ed",
        "<html></html>",
    ),
    (
        XS512EM,
        "1113244551",
        "6ca0965e7a44ee17eec5d575c8c56dd8",
        '<html><input name="Gambit" value="cookie_value"></html>',
    ),
    (GSS108E, "2082437949", "1c0714cfd1c8595db5ba36ceae43b134", "<html></html>"),
]
# Add models without a full set of pages with pytest.param(GSXYZ,
#   marks=pytest.mark.xfail(reason="no valid data pages"))
MODELS_FOR_GET_SWITCH_INFOS = [
    GS105Ev2,
    GS105PE,
    GS108Ev3,
    GS108PEv3,
    GS108Ev4,
    GS110EMX,
    GS305E,
    GS308E,
    GS308EP,
    GS308EPP,
    GS308Ev4,
    GS316EPP,
    JGS516PE,
    JGS524Ev2,
    XS512EM,
    GSS108E,
]

# List of models for reboot test, with
# reboot response code and if page content is returned
MODELS_FOR_REBOOT = [
    (GS105Ev2, 200, True),
    (GS108Ev3, 200, True),
    (GS308Ev4, 444, False),
    (GS308EP, 444, False),
    (GS308EPP, 444, False),
]

TEST_MODELS = [model[0] for model in MODEL_PARAMETERS]
PORT_SWITCH_MODELS = [
    switch_model for switch_model in TEST_MODELS if switch_model.SWITCH_PORT_TEMPLATES
]


class PyTestPageFetcher:
    """A class to fetch pages from a file."""

    def __init__(self, switch_model: type[AutodetectedSwitchModel]) -> None:
        """Initialize the PageFetcher."""
        self.switch_model = switch_model
        self._sequence = 0

    def next_sequence(self) -> int:
        """Get the next sequence number."""
        self._sequence += 1
        return self._sequence

    def from_file(
        self,
        templates: list[dict[str, str]],
        client_hash: str = "",
    ) -> requests.Response:
        """Fetch a page from a file."""
        del client_hash
        response = Mock()
        response.status_code = requests.codes.ok
        response.content = self.get_path(templates).read_bytes()
        return response

    def get_path(self, templates: list[dict[str, str]]) -> Path:
        """Get the path to the first page that exists as a file."""
        for template in templates:
            url = template["url"]
            page_name = url.split("/")[-1] or DEFAULT_PAGE
            path = Path(
                f"pages/{self.switch_model.MODEL_NAME}/{self._sequence}/{page_name}"
            )
            if path.exists():
                return path
        raise FileNotFoundError


def test_0_from_bytes_to_megabytes() -> None:
    """Test cases for _from_bytes_to_megabytes function."""
    assert _from_bytes_to_megabytes(1000000) == 1.00
    assert _from_bytes_to_megabytes(5000000) == 5.00
    assert _from_bytes_to_megabytes(123456789) == 123.46
    assert _from_bytes_to_megabytes(0) == 0.00
    assert _from_bytes_to_megabytes(-1000000) == -1.00


def test_0_netgear_switch_connector_initialization() -> None:
    """Test initialization of NetgearSwitchConnector."""
    connector = NetgearSwitchConnector(host="192.168.0.1", password="password")
    assert connector.host == "192.168.0.1"
    assert connector._password == "password"
    assert connector.switch_model is not None
    assert connector.ports == 0
    assert connector.poe_ports == []
    assert connector._switch_bootloader == "unknown"
    assert connector.sleep_time == 0.25
    assert connector._page_fetcher is not None
    assert connector._client_hash is None
    assert connector._gambit is None
    assert connector._previous_data == {}
    assert connector._loaded_switch_metadata == {}


@pytest.mark.parametrize(
    "switch_model",
    TEST_MODELS,
)
def test_autodetect_model(switch_model: type[AutodetectedSwitchModel]) -> None:
    """Test autodetect_model method."""
    page_fetcher = PyTestPageFetcher(switch_model)
    connector = NetgearSwitchConnector(host="192.168.0.1", password="password")
    with patch("py_netgear_plus.fetcher.requests.request") as mock_request:
        mock_response = Mock()
        with page_fetcher.get_path(switch_model.AUTODETECT_TEMPLATES).open() as file:
            mock_response.content = file.read()
        mock_response.status_code = requests.codes.ok
        mock_request.return_value = mock_response
        connector.autodetect_model()
        assert isinstance(connector.switch_model, switch_model)


@pytest.mark.parametrize(
    "switch_model",
    TEST_MODELS,
)
def test_check_login_url(switch_model: type[AutodetectedSwitchModel]) -> None:
    """Test check_login_url method."""
    page_fetcher = PyTestPageFetcher(switch_model)
    connector = NetgearSwitchConnector(host="192.168.0.1", password="password")
    with patch("py_netgear_plus.fetcher.requests.request") as mock_request:
        mock_response = Mock()
        with page_fetcher.get_path(switch_model.AUTODETECT_TEMPLATES).open() as file:
            mock_response.content = file.read()
        mock_response.status_code = requests.codes.ok
        mock_request.return_value = mock_response
        mock_response.status_code = requests.codes.ok
        mock_request.return_value = mock_response
        assert connector._page_fetcher.check_login_url(switch_model) is True
        assert connector._page_fetcher._login_page_response == mock_response
        checks = switch_model.CHECKS_AND_RESULTS
        if True in next(
            (check[1] for check in checks if check[0] == "check_login_form_rand"),
            [False],
        ):
            rand = connector._page_parser.parse_login_form_rand(
                connector._page_fetcher._login_page_response
            )
            assert rand is not None


@pytest.mark.parametrize(
    ("switch_model", "rand", "crypted_password", "content"),
    MODEL_PARAMETERS,
)
def test_parse_login_form_rand(
    switch_model: type[AutodetectedSwitchModel],
    rand: str,
    crypted_password: str,
    content: str,  # noqa: ARG001
) -> None:
    """Test check_login_form_rand method."""
    password = "Password1"
    connector = NetgearSwitchConnector(host="192.168.0.1", password=password)
    connector._page_fetcher._login_page_response = Mock()

    page_fetcher = PyTestPageFetcher(switch_model)
    with page_fetcher.get_path(switch_model.AUTODETECT_TEMPLATES).open() as file:
        connector._page_fetcher._login_page_response.content = file.read()

    connector._page_fetcher._login_page_response.status_code = requests.codes.ok
    assert (
        connector._page_parser.parse_login_form_rand(
            connector._page_fetcher._login_page_response
        )
        == rand
    )
    crypt_function = switch_model.CRYPT_FUNCTION
    if crypt_function == "hex_hmac_md5":
        assert hex_hmac_md5(password) == crypted_password
    elif crypt_function == "merge_hash":
        assert merge_hash(password, rand) == crypted_password
    else:
        pytest.fail(f"Unknown crypt function {crypt_function}")


@pytest.mark.parametrize(
    "switch_model",
    TEST_MODELS,
)
def test_get_unique_id(switch_model: type[AutodetectedSwitchModel]) -> None:
    """Test get_unique_id method."""
    connector = NetgearSwitchConnector(host="192.168.0.1", password="password")
    connector.switch_model = switch_model
    assert (
        connector.get_unique_id()
        == f"{connector.switch_model.__name__.lower()}_192_168_0_1"
    )


@pytest.mark.parametrize(
    ("switch_model", "rand", "crypted_password", "content"),
    MODEL_PARAMETERS,
)
def test_get_login_password(
    switch_model: AutodetectedSwitchModel,
    rand: str,
    crypted_password: str,
    content: str,  # noqa: ARG001
) -> None:
    """Test get_login_password method."""
    password = "Password1"
    connector = NetgearSwitchConnector(host="192.168.0.1", password=password)
    with patch("py_netgear_plus.fetcher.requests.request") as mock_request:
        mock_response = Mock()
        page_name = switch_model.LOGIN_TEMPLATE["url"].split("/")[-1] or DEFAULT_PAGE
        with Path(f"pages/{switch_model.MODEL_NAME}/0/{page_name}").open() as file:
            mock_response.content = file.read()
        mock_response.status_code = requests.codes.ok
        mock_request.return_value = mock_response
        connector._page_fetcher._login_page_response = mock_response
        crypt_function = switch_model.CRYPT_FUNCTION
        if crypt_function == "hex_hmac_md5":
            assert hex_hmac_md5(password) == crypted_password
        elif crypt_function == "merge_hash":
            assert merge_hash(password, rand) == crypted_password
        else:
            pytest.fail(f"Unknown crypt function {crypt_function}")


@pytest.mark.parametrize(
    ("switch_model", "rand", "crypted_password", "content"),
    MODEL_PARAMETERS,
)
def test_get_login_cookie(
    switch_model: AutodetectedSwitchModel,
    rand: str,
    crypted_password: str,  # noqa: ARG001
    content: str,
) -> None:
    """Test get_login_cookie method."""
    connector = NetgearSwitchConnector(host="192.168.0.1", password="Password1")
    connector.turn_on_offline_mode(f"pages/{switch_model.MODEL_NAME}/0")
    connector.autodetect_model()
    connector._page_fetcher.check_login_url(connector.switch_model)
    connector.turn_on_online_mode()

    key = next(
        (
            k
            for k, v in connector.switch_model.LOGIN_TEMPLATE["params"].items()
            if v == "_password_hash"
        ),
        None,
    )

    crypt_function = switch_model.CRYPT_FUNCTION
    if crypt_function == "hex_hmac_md5":
        data = {
            "submitId": "pwdLogin",
            key: hex_hmac_md5(connector._password),
            "submitEnd": "",
        }
    elif crypt_function == "merge_hash":
        data = {
            key: merge_hash(connector._password, rand),
        }
    else:
        pytest.fail(f"Unknown crypt function {crypt_function}")

    with (
        patch("py_netgear_plus.fetcher.requests.request") as mock_request,
    ):
        mock_response = Mock()
        mock_response.status_code = requests.codes.ok
        mock_response.content = content
        mock_response.cookies.get.return_value = "cookie_value"
        mock_request.return_value = mock_response
        assert connector.get_login_cookie() is True
        mock_request.assert_called()
        mock_request.assert_called_with(
            connector.switch_model.LOGIN_TEMPLATE["method"],
            connector.switch_model.LOGIN_TEMPLATE["url"].format(ip=connector.host),
            data=data,
            allow_redirects=True,
            timeout=URL_REQUEST_TIMEOUT,
        )
        (cookie_name, cookie_value) = connector.get_cookie()
        assert cookie_name is not None
        assert cookie_value == "cookie_value"


@pytest.mark.parametrize(
    ("page", "expected"),
    [
        ("GS108Ev3/0/index.htm", True),
        ("GS308EP/unauthenticated.html", False),
        ("GS308EP/0/dashboard.cgi", True),
        ("GS308EP/0/portStatistics.cgi", True),
        ("GS308EPP/0/dashboard.cgi", True),
        ("GS308EPP/0/portStatistics.cgi", True),
        ("GS316EPP/unauthenticated.html", False),
        ("GS316EPP/0/dashboard.html", True),
    ],
)
def test_is_authenticated(page: str, expected: bool) -> None:  # noqa: FBT001
    """Test is_authenticated method."""
    connector = NetgearSwitchConnector(host="192.168.0.1", password="XXXXXXXX")
    response = Mock()
    response.content = Path(f"pages/{page}").read_text()
    response.status_code = requests.codes.ok
    assert connector._page_fetcher._is_authenticated(response) is expected


@pytest.mark.parametrize(
    "switch_model",
    MODELS_FOR_GET_SWITCH_INFOS,
)
def test_get_switch_infos(switch_model: type[AutodetectedSwitchModel]) -> None:
    """Test initialization of NetgearSwitchConnector."""
    with (
        patch("py_netgear_plus.time.perf_counter", return_value=0),
        patch(
            "py_netgear_plus.NetgearSwitchConnector.fetch_page_from_templates"
        ) as mock_fetch_page_from_templates,
    ):
        page_fetcher = PyTestPageFetcher(switch_model)
        mock_fetch_page_from_templates.side_effect = page_fetcher.from_file
        connector = NetgearSwitchConnector(host="192.168.0.1", password="password")
        with patch("py_netgear_plus.fetcher.requests.request") as mock_request:
            mock_response = Mock()
            with page_fetcher.get_path(
                switch_model.AUTODETECT_TEMPLATES
            ).open() as file:
                mock_response.content = file.read()
            mock_response.status_code = requests.codes.ok
            mock_request.return_value = mock_response
            connector.autodetect_model()
        assert isinstance(connector.switch_model, switch_model)
        connector._page_fetcher._login_page_response = Mock()
        with page_fetcher.get_path([switch_model.LOGIN_TEMPLATE]).open() as file:
            connector._page_fetcher._login_page_response.content = file.read()
        for sequence in range(2):
            connector._page_fetcher._login_page_response.status_code = requests.codes.ok
            switch_data = connector.get_switch_infos()
            with Path(
                f"pages/{switch_model.MODEL_NAME}/{sequence}/switch_infos.json"
            ).open() as file:
                validation_data = json.loads(file.read())
                assert switch_data == validation_data
            page_fetcher.next_sequence()


@pytest.mark.parametrize(
    "switch_model",
    PORT_SWITCH_MODELS,
)
def test_turn_on_and_off_port(switch_model: type[AutodetectedSwitchModel]) -> None:
    """Test turning on/off a regular port."""
    with (
        patch(
            "py_netgear_plus.NetgearSwitchConnector.fetch_page_from_templates"
        ) as mock_fetch_page_from_templates,
    ):
        page_fetcher = PyTestPageFetcher(switch_model)
        mock_fetch_page_from_templates.side_effect = page_fetcher.from_file

        connector = NetgearSwitchConnector(host="192.168.0.1", password="password")

        with patch("py_netgear_plus.fetcher.requests.request") as mock_request:
            mock_response = Mock()
            with page_fetcher.get_path(
                switch_model.AUTODETECT_TEMPLATES
            ).open() as file:
                mock_response.content = file.read()
            mock_response.status_code = requests.codes.ok
            mock_request.return_value = mock_response
            connector.autodetect_model()
        assert isinstance(connector.switch_model, switch_model)

        connector._client_hash = "client_hash"
        connector._gambit = "gambit"
        connector.set_cookie("cookie_name", "cookie_value")

        response = Mock()
        response.status_code = requests.codes.ok
        response.content = b"SUCCESS"
        with patch(
            "py_netgear_plus.fetcher.requests.request",
            return_value=response,
        ) as mock_request:
            cookies = requests.cookies.RequestsCookieJar()
            cookies.set(
                str(connector.get_cookie()[0]),
                str(connector.get_cookie()[1]),
                domain=connector.host,
                path="/",
            )

            mock_request.return_value = response

            for state in ["on", "off"]:
                port = 1
                data = connector.switch_model.get_switch_port_data(port, state)
                # Mocking get_switch_infos because switch_port calls it
                with patch(
                    "py_netgear_plus.NetgearSwitchConnector.get_switch_infos",
                    return_value={
                        f"port_{port}_description": "Test",
                        f"port_{port}_flow_control": "enable",
                    },
                ):
                    assert connector.switch_port(port, state) is True
                    if state == "on":
                        assert connector.turn_on_port(port) is True
                    else:
                        assert connector.turn_off_port(port) is True

                mock_request.assert_called()
                # data will be updated by set_data_from_template inside switch_port
                # but we can check if it was called with correct url and method
                expected_data = data.copy()
                expected_data["DESCRIPTION"] = "Test"
                expected_data["FLOW_CONTROL"] = 1
                if connector._client_hash:
                    expected_data["hash"] = connector._client_hash
                mock_request.assert_called_with(
                    connector.switch_model.SWITCH_PORT_TEMPLATES[0]["method"],
                    connector.switch_model.SWITCH_PORT_TEMPLATES[0]["url"].format(
                        ip=connector.host
                    ),
                    data=expected_data,
                    cookies=cookies,
                    timeout=URL_REQUEST_TIMEOUT,
                    allow_redirects=False,
                )


@pytest.mark.parametrize(
    "switch_model",
    PORT_SWITCH_MODELS,
)
def test_switch_port_uses_model_defaults_when_optional_fields_missing(
    switch_model: type[AutodetectedSwitchModel],
) -> None:
    """Test switching a port without description/flow-control data."""
    connector = NetgearSwitchConnector(host="192.168.0.1", password="password")
    connector._set_instance_attributes_by_model(switch_model())
    connector._client_hash = "client_hash"
    connector.set_cookie("cookie_name", "cookie_value")

    response = Mock()
    response.status_code = requests.codes.ok
    response.content = b"SUCCESS"
    with patch(
        "py_netgear_plus.fetcher.requests.request",
        return_value=response,
    ) as mock_request:
        cookies = requests.cookies.RequestsCookieJar()
        cookies.set(
            str(connector.get_cookie()[0]),
            str(connector.get_cookie()[1]),
            domain=connector.host,
            path="/",
        )

        port = 1
        with patch(
            "py_netgear_plus.NetgearSwitchConnector.get_switch_infos",
            return_value={},
        ):
            assert connector.switch_port(port, "off") is True

        expected_data = connector.switch_model.get_switch_port_data(port, "off").copy()
        expected_data["hash"] = connector._client_hash
        mock_request.assert_called_with(
            connector.switch_model.SWITCH_PORT_TEMPLATES[0]["method"],
            connector.switch_model.SWITCH_PORT_TEMPLATES[0]["url"].format(
                ip=connector.host
            ),
            data=expected_data,
            cookies=cookies,
            timeout=URL_REQUEST_TIMEOUT,
            allow_redirects=False,
        )


@pytest.mark.parametrize(
    "switch_model",
    PORT_SWITCH_MODELS,
)
def test_switch_port_autodetects_before_validating_port_range(
    switch_model: type[AutodetectedSwitchModel],
) -> None:
    """Test switch_port performs lazy autodetection."""
    connector = NetgearSwitchConnector(host="192.168.0.1", password="password")

    def _autodetect() -> type[AutodetectedSwitchModel]:
        connector._set_instance_attributes_by_model(switch_model())
        return switch_model

    with patch.object(connector, "autodetect_model", side_effect=_autodetect):
        connector._client_hash = "client_hash"
        connector.set_cookie("cookie_name", "cookie_value")

        response = Mock()
        response.status_code = requests.codes.ok
        response.content = b"SUCCESS"
        with (
            patch(
                "py_netgear_plus.fetcher.requests.request",
                return_value=response,
            ),
            patch(
                "py_netgear_plus.NetgearSwitchConnector.get_switch_infos",
                return_value={},
            ),
        ):
            assert connector.turn_off_port(1) is True


@pytest.mark.parametrize(
    "switch_model",
    PORT_SWITCH_MODELS,
)
def test_switch_port_accepts_pending_apply_page(
    switch_model: type[AutodetectedSwitchModel],
) -> None:
    """Test switching a port when the switch replies with a wait page."""
    connector = NetgearSwitchConnector(host="192.168.0.1", password="password")
    connector._set_instance_attributes_by_model(switch_model())
    connector._client_hash = "client_hash"
    connector.set_cookie("cookie_name", "cookie_value")

    response = Mock()
    response.status_code = requests.codes.ok
    response.content = b"""<!DOCTYPE html>
<html>
<head>
<meta http-equiv="refresh" content = 4>
</head>
<body>Please wait...<input type='hidden' name='hash' value='4554'></body>
</html>"""

    with (
        patch(
            "py_netgear_plus.fetcher.requests.request",
            return_value=response,
        ),
        patch("py_netgear_plus.time.sleep") as mock_sleep,
        patch(
            "py_netgear_plus.NetgearSwitchConnector.get_switch_infos",
            return_value={},
        ),
    ):
        assert connector.turn_off_port(1) is True
        mock_sleep.assert_called_with(4.0)
        assert connector._client_hash == "4554"


@pytest.mark.parametrize(
    "switch_model",
    TEST_MODELS,
)
def test_turn_on_and_off_poe_port(switch_model: type[AutodetectedSwitchModel]) -> None:
    """Test turning on/off power on a PoE port."""
    with (
        patch(
            "py_netgear_plus.NetgearSwitchConnector.fetch_page_from_templates"
        ) as mock_fetch_page_from_templates,
    ):
        page_fetcher = PyTestPageFetcher(switch_model)
        mock_fetch_page_from_templates.side_effect = page_fetcher.from_file

        connector = NetgearSwitchConnector(host="192.168.0.1", password="password")

        with patch("py_netgear_plus.fetcher.requests.request") as mock_request:
            mock_response = Mock()
            with page_fetcher.get_path(
                switch_model.AUTODETECT_TEMPLATES
            ).open() as file:
                mock_response.content = file.read()
            mock_response.status_code = requests.codes.ok
            mock_request.return_value = mock_response
            connector.autodetect_model()
        assert isinstance(connector.switch_model, switch_model)
        assert isinstance(connector.switch_model.POE_PORTS, list)
        if len(connector.switch_model.POE_PORTS) == 0:
            pytest.skip(f"Model {switch_model.MODEL_NAME} has no PoE ports.")

        connector._client_hash = "client_hash"
        connector._gambit = "gambit"
        connector.set_cookie("cookie_name", "cookie_value")

        response = BaseResponse()
        response.status_code = requests.codes.ok
        response.content = b"SUCCESS"
        with patch(
            "py_netgear_plus.fetcher.requests.request",
            return_value=response,
        ) as mock_request:
            cookies = requests.cookies.RequestsCookieJar()
            cookies.set(
                str(connector.get_cookie()[0]),
                str(connector.get_cookie()[1]),
                domain=connector.host,
                path="/",
            )

            mock_request.return_value = response

            for state in ["on", "off"]:
                poe_port = connector.switch_model.POE_PORTS[0]
                data = connector.switch_model.get_switch_poe_port_data(poe_port, state)
                connector._page_fetcher.set_data_from_template(
                    connector.switch_model.SWITCH_POE_PORT_TEMPLATES[0], connector, data
                )
                connector.switch_poe_port(poe_port, state)
                mock_request.assert_called()
                mock_request.assert_called_with(
                    connector.switch_model.SWITCH_POE_PORT_TEMPLATES[0]["method"],
                    connector.switch_model.SWITCH_POE_PORT_TEMPLATES[0]["url"].format(
                        ip=connector.host
                    ),
                    data=data,
                    cookies=cookies,
                    timeout=URL_REQUEST_TIMEOUT,
                    allow_redirects=False,
                )


@pytest.mark.parametrize(
    ("port_suffix", "expected_cookie_port"),
    [("", None), (":80", "80"), (":1337", "1337")],
)
def test_non_standard_tcp_ports(port_suffix: str, expected_cookie_port: int) -> None:
    """Test whether cookie port and domain are split correctly."""
    response = BaseResponse()
    response.status_code = requests.codes.ok
    response.content = b"SUCCESS"
    with patch(
        "py_netgear_plus.fetcher.requests.request",
        return_value=response,
    ) as mock_request:
        mock_request.return_value = response
        host_portion = "192.168.0.1"
        concatenated = f"{host_portion}{port_suffix}"

        connector = NetgearSwitchConnector(host=concatenated, password="password")
        connector.set_cookie("demo", "demo")

        connector._page_fetcher.request("get", concatenated)

    mock_request.assert_called_once()

    assert "cookies" in mock_request.call_args.kwargs
    cookies = list(mock_request.call_args.kwargs["cookies"])

    assert len(cookies) == 1
    only_cookie: Cookie = cookies.pop()
    assert only_cookie.port == expected_cookie_port
    assert only_cookie.domain == host_portion


@pytest.mark.parametrize(
    ("switch_model", "status_code", "has_content"),
    MODELS_FOR_REBOOT,
)
def test_reboot(
    switch_model: type[AutodetectedSwitchModel],
    status_code: int,
    has_content: bool,  # noqa: FBT001
) -> None:
    """Test switch reboot."""
    if not switch_model.SWITCH_REBOOT_TEMPLATES:
        pytest.skip(f"Model {switch_model.MODEL_NAME} does not support reboot.")

    assert switch_model.SWITCH_REBOOT_TEMPLATES

    with (
        patch(
            "py_netgear_plus.NetgearSwitchConnector.fetch_page_from_templates"
        ) as mock_fetch_page_from_templates,
    ):
        page_fetcher = PyTestPageFetcher(switch_model)
        mock_fetch_page_from_templates.side_effect = page_fetcher.from_file

        connector = NetgearSwitchConnector(host="192.168.0.1", password="password")

        with patch("py_netgear_plus.fetcher.requests.request") as mock_request:
            mock_response = Mock()
            with page_fetcher.get_path(
                switch_model.AUTODETECT_TEMPLATES
            ).open() as file:
                mock_response.content = file.read()
            mock_response.status_code = requests.codes.ok
            mock_request.return_value = mock_response
            connector.autodetect_model()
        assert isinstance(connector.switch_model, switch_model)

        connector._client_hash = "client_hash"
        connector._gambit = "gambit"
        connector.set_cookie("cookie_name", "cookie_value")

        response = Mock()
        response.status_code = status_code

        # some switches don't return any content on a reboot, thus
        # we need to have the ability to not load a page
        if has_content:
            with page_fetcher.get_path(
                switch_model.SWITCH_REBOOT_TEMPLATES
            ).open() as file:
                response.content = file.read()
        else:
            response.content = None

        with patch(
            "py_netgear_plus.fetcher.requests.request",
            return_value=response,
        ) as mock_request:
            cookies = requests.cookies.RequestsCookieJar()
            cookies.set(
                str(connector.get_cookie()[0]),
                str(connector.get_cookie()[1]),
                domain=connector.host,
                path="/",
            )

            mock_request.return_value = response

            data = {}
            connector._page_fetcher.set_data_from_template(
                connector.switch_model.SWITCH_REBOOT_TEMPLATES[0], connector, data
            )

            assert connector.reboot() is True

            mock_request.assert_called()
            mock_request.assert_called_with(
                connector.switch_model.SWITCH_REBOOT_TEMPLATES[0]["method"],
                connector.switch_model.SWITCH_REBOOT_TEMPLATES[0]["url"].format(
                    ip=connector.host
                ),
                data=data,
                cookies=cookies,
                timeout=URL_REQUEST_TIMEOUT,
                allow_redirects=False,
            )


class JsonApiTestHelper:
    """Helper for JSON REST API switch tests (MS3xx series)."""

    def __init__(self, model_name: str) -> None:
        """Initialize the JSON API test helper."""
        self.data_dir = Path(f"pages/{model_name}")
        self._sequence = 0

    def next_sequence(self) -> int:
        """Get the next sequence number."""
        self._sequence += 1
        return self._sequence

    @staticmethod
    def make_json_response(filepath: Path) -> Mock:
        """Create a mock response from a JSON file."""
        resp = Mock()
        resp.status_code = requests.codes.ok
        content = filepath.read_bytes()
        resp.content = content
        resp.json.return_value = json.loads(content)
        return resp

    @staticmethod
    def make_json_body_response(
        body: object, status_code: int = requests.codes.ok
    ) -> Mock:
        """Create a mock response from an inline sanitized JSON body."""
        resp = Mock()
        resp.status_code = status_code
        resp.json.return_value = body
        return resp

    def mock_json_request(self, method: str, url: str, **kwargs: dict) -> Mock:  # noqa: ARG002
        """Mock json_request based on URL."""
        if "/api/system/status" in url:
            return self.make_json_response(self.data_dir / "system_status.json")
        if "/api/system/login" in url:
            return self.make_json_response(self.data_dir / "login.json")
        if "/api/login_session" in url:
            return self.make_json_response(self.data_dir / "login_session.json")
        if "/api/ports/statistics" in url:
            return self.make_json_response(
                self.data_dir / str(self._sequence) / "ports_statistics.json"
            )
        if "/api/ports" in url:
            return self.make_json_response(
                self.data_dir / str(self._sequence) / "ports.json"
            )
        resp = Mock()
        resp.status_code = requests.codes.not_found
        return resp


JSON_API_MODELS = [
    (MS305E, 5),
    (MS308E, 8),
]
JSON_API_MODEL_CLASSES = [switch_model for switch_model, _ in JSON_API_MODELS]


@pytest.mark.parametrize(
    ("has_bearer_token", "err_code", "expected_status"),
    [
        (True, -2, status_code_unauthorized),
        (True, "-2", status_code_unauthorized),
        (False, -2, status_code_unauthorized),
        (False, 0, requests.codes.ok),
        (False, -3, requests.codes.ok),
    ],
)
def test_json_request_recognizes_authentication_error(
    has_bearer_token: bool,  # noqa: FBT001
    err_code: int | str,
    expected_status: int,
) -> None:
    """Recognize only the observed JSON authentication error code."""
    fetcher = PageFetcher("switch.test")
    if has_bearer_token:
        fetcher.set_bearer_token("expired")
    response = Mock()
    response.status_code = requests.codes.ok
    response.json.return_value = {"errCode": err_code}

    with patch("py_netgear_plus.fetcher.requests.request", return_value=response):
        result = fetcher.json_request("get", "http://switch.test/api/ports")

    assert result.status_code == expected_status


def test_json_request_preserves_status_for_malformed_json() -> None:
    """Do not reinterpret malformed response bodies as authentication errors."""
    fetcher = PageFetcher("switch.test")
    response = Mock()
    response.status_code = requests.codes.ok
    response.json.side_effect = ValueError

    with patch("py_netgear_plus.fetcher.requests.request", return_value=response):
        result = fetcher.json_request("get", "http://switch.test/api/ports")

    assert result.status_code == requests.codes.ok


def test_json_request_marks_timeout_as_no_response() -> None:
    """Preserve timeout identity for JSON request recovery."""
    fetcher = PageFetcher("switch.test")

    with patch(
        "py_netgear_plus.fetcher.requests.request",
        side_effect=requests.exceptions.Timeout,
    ):
        result = fetcher.json_request("get", "http://switch.test/api/ports")

    assert result.status_code == status_code_no_response


@pytest.mark.parametrize("switch_model", JSON_API_MODEL_CLASSES)
def test_json_api_fetch_retries_get_after_timeout(
    switch_model: type[AutodetectedSwitchModel],
) -> None:
    """Retry one timed-out JSON GET for each MS3xx model."""
    connector = NetgearSwitchConnector(host="switch.test", password="password")
    connector._set_instance_attributes_by_model(switch_model())
    timeout_response = BaseResponse()
    timeout_response.status_code = status_code_no_response
    success_response = JsonApiTestHelper.make_json_response(
        Path(f"pages/{switch_model.MODEL_NAME}/0/ports.json")
    )

    with patch.object(
        connector._page_fetcher,
        "json_request",
        side_effect=[timeout_response, success_response],
    ) as mock_json_request:
        result = connector._json_api_fetch(switch_model.PORT_STATUS_TEMPLATES)

    assert result is success_response
    assert mock_json_request.call_count == 2


@pytest.mark.parametrize("switch_model", JSON_API_MODEL_CLASSES)
def test_json_api_fetch_retries_get_after_second_timeout(
    switch_model: type[AutodetectedSwitchModel],
) -> None:
    """Recover when the first two JSON GET attempts time out."""
    connector = NetgearSwitchConnector(host="switch.test", password="password")
    connector._set_instance_attributes_by_model(switch_model())
    timeout_response = BaseResponse()
    timeout_response.status_code = status_code_no_response
    success_response = JsonApiTestHelper.make_json_response(
        Path(f"pages/{switch_model.MODEL_NAME}/0/ports.json")
    )

    with patch.object(
        connector._page_fetcher,
        "json_request",
        side_effect=[timeout_response, timeout_response, success_response],
    ) as mock_json_request:
        result = connector._json_api_fetch(switch_model.PORT_STATUS_TEMPLATES)

    assert result is success_response
    assert mock_json_request.call_count == 3


@pytest.mark.parametrize("switch_model", JSON_API_MODEL_CLASSES)
def test_json_api_fetch_stops_after_third_timeout(
    switch_model: type[AutodetectedSwitchModel],
) -> None:
    """Keep the JSON GET timeout recovery bounded to three attempts."""
    connector = NetgearSwitchConnector(host="switch.test", password="password")
    connector._set_instance_attributes_by_model(switch_model())
    timeout_response = BaseResponse()
    timeout_response.status_code = status_code_no_response

    with (
        patch.object(
            connector._page_fetcher,
            "json_request",
            return_value=timeout_response,
        ) as mock_json_request,
        pytest.raises(PageNotLoadedError),
    ):
        connector._json_api_fetch(switch_model.PORT_STATUS_TEMPLATES)

    assert mock_json_request.call_count == 3


@pytest.mark.parametrize("switch_model", JSON_API_MODEL_CLASSES)
def test_json_api_fetch_clears_expired_token_before_login(
    switch_model: type[AutodetectedSwitchModel],
) -> None:
    """Renew an expired MS3xx session without sending its stale token."""
    helper = JsonApiTestHelper(switch_model.MODEL_NAME)
    connector = NetgearSwitchConnector(host="switch.test", password="password")
    connector._set_instance_attributes_by_model(switch_model())
    connector._page_fetcher.set_bearer_token("expired")
    unauthorized_response = Mock()
    unauthorized_response.status_code = status_code_unauthorized
    port_response = helper.make_json_response(helper.data_dir / "0" / "ports.json")
    port_requests = 0

    def mock_json_request(method: str, url: str, **kwargs: dict) -> Mock:  # noqa: ARG001
        nonlocal port_requests
        if "/api/system/login" in url:
            assert connector._page_fetcher.has_bearer_token() is False
            return helper.make_json_response(helper.data_dir / "login.json")
        if "/api/login_session" in url:
            assert connector._page_fetcher.has_bearer_token() is True
            return helper.make_json_response(helper.data_dir / "login_session.json")
        if "/api/ports" in url:
            port_requests += 1
            if port_requests == 1:
                return unauthorized_response
            return port_response
        pytest.fail(f"Unexpected JSON API URL: {url}")

    with patch.object(
        connector._page_fetcher,
        "json_request",
        side_effect=mock_json_request,
    ):
        result = connector._json_api_fetch(switch_model.PORT_STATUS_TEMPLATES)

    assert result is port_response
    assert port_requests == 2
    assert connector._page_fetcher.has_bearer_token() is True


@pytest.mark.parametrize("switch_model", JSON_API_MODEL_CLASSES)
def test_json_api_fetch_recovers_after_session_registration_http_500(
    switch_model: type[AutodetectedSwitchModel],
) -> None:
    """Recover the observed expired-session and registration failure sequence."""
    helper = JsonApiTestHelper(switch_model.MODEL_NAME)
    connector = NetgearSwitchConnector(host="switch.test", password="password")
    connector._set_instance_attributes_by_model(switch_model())
    connector._page_fetcher.set_bearer_token("expired")
    unauthorized_response = Mock(status_code=status_code_unauthorized)
    login_response = helper.make_json_response(helper.data_dir / "login.json")
    session_id = login_response.json.return_value["id"]
    server_error = Mock(status_code=requests.codes.internal_server_error)
    server_error.json.side_effect = ValueError
    session_response = helper.make_json_response(helper.data_dir / "login_session.json")
    port_response = helper.make_json_response(helper.data_dir / "0" / "ports.json")

    with patch.object(
        connector._page_fetcher,
        "json_request",
        side_effect=[
            unauthorized_response,
            login_response,
            server_error,
            session_response,
            port_response,
        ],
    ) as mock_json_request:
        result = connector._json_api_fetch(switch_model.PORT_STATUS_TEMPLATES)

    assert result is port_response
    assert mock_json_request.call_args_list == [
        call("get", "http://switch.test/api/ports"),
        call(
            "patch",
            "http://switch.test/api/system/login",
            data={"password": "password"},
        ),
        call(
            "post",
            "http://switch.test/api/login_session",
            data={"id": session_id, "status": True},
        ),
        call(
            "post",
            "http://switch.test/api/login_session",
            data={"id": session_id, "status": True},
        ),
        call("get", "http://switch.test/api/ports"),
    ]


@pytest.mark.parametrize("switch_model", JSON_API_MODEL_CLASSES)
def test_json_api_fetch_refreshes_active_session_every_minute(
    switch_model: type[AutodetectedSwitchModel],
) -> None:
    """Refresh the same active session at the cadence observed on both switches."""
    helper = JsonApiTestHelper(switch_model.MODEL_NAME)
    connector = NetgearSwitchConnector(host="switch.test", password="password")
    connector._set_instance_attributes_by_model(switch_model())
    connector._json_session_id = "active-session"
    connector._json_session_refreshed_at = 0
    port_response = helper.make_json_response(helper.data_dir / "0" / "ports.json")
    session_response = helper.make_json_response(helper.data_dir / "login_session.json")

    with (
        patch("py_netgear_plus.time.monotonic", return_value=59),
        patch.object(
            connector._page_fetcher,
            "json_request",
            return_value=port_response,
        ) as mock_json_request,
    ):
        connector._json_api_fetch(switch_model.PORT_STATUS_TEMPLATES)

    mock_json_request.assert_called_once_with("get", "http://switch.test/api/ports")

    with (
        patch("py_netgear_plus.time.monotonic", return_value=60),
        patch.object(
            connector._page_fetcher,
            "json_request",
            side_effect=[session_response, port_response],
        ) as mock_json_request,
    ):
        result = connector._json_api_fetch(switch_model.PORT_STATUS_TEMPLATES)

    assert result is port_response
    assert connector._json_session_refreshed_at == 60
    assert mock_json_request.call_args_list == [
        call(
            "post",
            "http://switch.test/api/login_session",
            data={"id": "active-session", "status": True},
        ),
        call("get", "http://switch.test/api/ports"),
    ]


@pytest.mark.parametrize(
    ("status_code", "body", "expected_log"),
    [
        (requests.codes.ok, {}, "session refresh rejected: errCode=None"),
        (
            requests.codes.ok,
            [],
            "session refresh returned an invalid body: body_type=list",
        ),
        (requests.codes.ok, {"errCode": -2}, "session refresh rejected: errCode=-2"),
        (
            status_code_unauthorized,
            {"errCode": 0},
            "session refresh rejected: http_status=401 body_type=dict errCode=0",
        ),
        (
            requests.codes.internal_server_error,
            {"errCode": -7, "message": "not logged"},
            "session refresh rejected: http_status=500 body_type=dict errCode=-7",
        ),
    ],
)
def test_json_api_keepalive_rejects_unsuccessful_response(
    caplog: pytest.LogCaptureFixture,
    status_code: int,
    body: object,
    expected_log: str,
) -> None:
    """Do not mark malformed or failed keepalive responses as successful."""
    caplog.set_level(logging.DEBUG, logger="py_netgear_plus")
    connector = NetgearSwitchConnector(host="switch.test", password="password")
    connector._set_instance_attributes_by_model(MS305E())
    connector._json_session_id = "active-session"
    connector._json_session_refreshed_at = 0
    response = JsonApiTestHelper.make_json_body_response(body, status_code)

    with (
        patch("py_netgear_plus.time.monotonic", return_value=60),
        patch.object(
            connector._page_fetcher,
            "json_request",
            return_value=response,
        ) as mock_json_request,
    ):
        assert connector._json_api_keepalive() is False

    assert mock_json_request.call_count == 1
    assert connector._json_session_refreshed_at == 0
    assert expected_log in caplog.text


def test_json_api_keepalive_diagnostics_handle_non_json_error_response(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Report only response shape when a failed session response is not JSON."""
    caplog.set_level(logging.DEBUG, logger="py_netgear_plus")
    connector = NetgearSwitchConnector(host="switch.test", password="password")
    connector._set_instance_attributes_by_model(MS308E())
    connector._json_session_id = "active-session"
    response = Mock(status_code=requests.codes.internal_server_error)
    response.json.side_effect = ValueError

    with patch.object(
        connector._page_fetcher,
        "json_request",
        return_value=response,
    ):
        assert connector._json_api_keepalive(force=True) is False

    assert "http_status=500 body_type=unavailable errCode=None" in caplog.text


@pytest.mark.parametrize(
    "case",
    [
        (
            status_code_unauthorized,
            {"errCode": 0},
            None,
            None,
            1,
            "login rejected: http_status=401 body_type=dict errCode=0",
        ),
        (
            requests.codes.ok,
            [],
            None,
            None,
            1,
            "login returned an invalid body: body_type=list",
        ),
        (
            requests.codes.ok,
            {"errCode": -2},
            None,
            None,
            1,
            "login rejected: errCode=-2",
        ),
        (
            requests.codes.ok,
            {"errCode": 0, "token": "new"},
            None,
            None,
            1,
            "valid_token=True valid_session_id=False",
        ),
        (
            requests.codes.ok,
            {
                "errCode": 0,
                "token": "new",
                "id": "new-session",
                "sessionmax": True,
                "timeout": 120,
            },
            status_code_unauthorized,
            {"errCode": 0},
            2,
            "login session registration failed: sessionmax=True timeout=120",
        ),
        (
            requests.codes.ok,
            {
                "errCode": 0,
                "token": "new",
                "id": "new-session",
                "sessionmax": False,
                "timeout": 120,
            },
            requests.codes.ok,
            {},
            2,
            "login session registration failed: sessionmax=False timeout=120",
        ),
    ],
)
def test_json_api_login_clears_state_after_unsuccessful_response(
    caplog: pytest.LogCaptureFixture,
    case: tuple[int, object, int | None, object, int, str],
) -> None:
    """Reject malformed or failed login steps without retaining session state."""
    (
        login_status,
        login_body,
        session_status,
        session_body,
        call_count,
        expected_log,
    ) = case
    caplog.set_level(logging.DEBUG, logger="py_netgear_plus")
    connector = NetgearSwitchConnector(host="switch.test", password="password")
    connector._set_instance_attributes_by_model(MS305E())
    connector._page_fetcher.set_bearer_token("expired")
    connector._json_session_id = "expired-session"
    connector._json_session_refreshed_at = 0
    responses = [JsonApiTestHelper.make_json_body_response(login_body, login_status)]
    if session_status is not None:
        responses.append(
            JsonApiTestHelper.make_json_body_response(session_body, session_status)
        )

    with patch.object(
        connector._page_fetcher,
        "json_request",
        side_effect=responses,
    ) as mock_json_request:
        assert connector._json_api_login() is False

    assert mock_json_request.call_count == call_count
    assert connector._page_fetcher.has_bearer_token() is False
    assert connector._json_session_id is None
    assert connector._json_session_refreshed_at is None
    assert expected_log in caplog.text


def test_json_api_login_diagnostics_do_not_log_sensitive_values(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Report a login failure without logging request or response secrets."""
    caplog.set_level(logging.DEBUG, logger="py_netgear_plus")
    connector = NetgearSwitchConnector(
        host="private-switch.test", password="private-password"
    )
    connector._set_instance_attributes_by_model(MS308E())
    response = JsonApiTestHelper.make_json_body_response(
        {
            "errCode": "private-error-code",
            "message": "private-message",
            "token": "private-token",
            "id": "private-session",
        }
    )
    caplog.clear()

    with patch.object(
        connector._page_fetcher,
        "json_request",
        return_value=response,
    ):
        assert connector._json_api_login() is False

    assert "login rejected: errCode=<str>" in caplog.text
    for private_value in (
        "private-switch.test",
        "private-password",
        "private-error-code",
        "private-message",
        "private-token",
        "private-session",
    ):
        assert private_value not in caplog.text


def test_json_api_session_registration_diagnostics_do_not_log_sensitive_values(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Report registration metadata without logging arbitrary response values."""
    caplog.set_level(logging.DEBUG, logger="py_netgear_plus")
    connector = NetgearSwitchConnector(
        host="private-switch.test", password="private-password"
    )
    connector._set_instance_attributes_by_model(MS305E())
    login_response = JsonApiTestHelper.make_json_body_response(
        {
            "errCode": 0,
            "token": "private-token",
            "id": "private-session",
            "sessionmax": "private-sessionmax",
            "timeout": "private-timeout",
        }
    )
    session_response = JsonApiTestHelper.make_json_body_response(
        {
            "errCode": "private-registration-code",
            "message": "private-message",
        },
        requests.codes.internal_server_error,
    )
    caplog.clear()

    with patch.object(
        connector._page_fetcher,
        "json_request",
        side_effect=[login_response, session_response, session_response],
    ):
        assert connector._json_api_login() is False

    assert "http_status=500 body_type=dict errCode=<str>" in caplog.text
    assert "sessionmax=<str> timeout=<str>" in caplog.text
    for private_value in (
        "private-switch.test",
        "private-password",
        "private-registration-code",
        "private-sessionmax",
        "private-timeout",
        "private-message",
        "private-token",
        "private-session",
    ):
        assert private_value not in caplog.text


@pytest.mark.parametrize("switch_model", JSON_API_MODEL_CLASSES)
def test_json_api_login_retries_transient_session_registration_http_500(
    caplog: pytest.LogCaptureFixture,
    switch_model: type[AutodetectedSwitchModel],
) -> None:
    """Retry the observed transient registration failure once for MS30xE."""
    caplog.set_level(logging.DEBUG, logger="py_netgear_plus")
    connector = NetgearSwitchConnector(host="switch.test", password="password")
    connector._set_instance_attributes_by_model(switch_model())
    login_response = JsonApiTestHelper.make_json_body_response(
        {
            "errCode": 0,
            "token": "new-token",
            "id": "new-session",
            "sessionmax": False,
            "timeout": 120,
        }
    )
    server_error = Mock(status_code=requests.codes.internal_server_error)
    server_error.json.side_effect = ValueError
    session_response = JsonApiTestHelper.make_json_body_response({"errCode": 0})

    with patch.object(
        connector._page_fetcher,
        "json_request",
        side_effect=[login_response, server_error, session_response],
    ) as mock_json_request:
        assert connector._json_api_login() is True

    assert mock_json_request.call_args_list == [
        call(
            "patch",
            "http://switch.test/api/system/login",
            data={"password": "password"},
        ),
        call(
            "post",
            "http://switch.test/api/login_session",
            data={"id": "new-session", "status": True},
        ),
        call(
            "post",
            "http://switch.test/api/login_session",
            data={"id": "new-session", "status": True},
        ),
    ]
    assert connector._page_fetcher.has_bearer_token() is True
    assert connector._json_session_id == "new-session"
    assert "session registration returned HTTP 500; retrying once" in caplog.text


@pytest.mark.parametrize("switch_model", JSON_API_MODEL_CLASSES)
def test_json_api_login_stops_after_second_session_registration_http_500(
    switch_model: type[AutodetectedSwitchModel],
) -> None:
    """Keep the observed session-registration retry bounded to one retry."""
    connector = NetgearSwitchConnector(host="switch.test", password="password")
    connector._set_instance_attributes_by_model(switch_model())
    login_response = JsonApiTestHelper.make_json_body_response(
        {
            "errCode": 0,
            "token": "new-token",
            "id": "new-session",
            "sessionmax": False,
            "timeout": 120,
        }
    )
    first_server_error = Mock(status_code=requests.codes.internal_server_error)
    first_server_error.json.side_effect = ValueError
    second_server_error = Mock(status_code=requests.codes.internal_server_error)
    second_server_error.json.side_effect = ValueError

    with patch.object(
        connector._page_fetcher,
        "json_request",
        side_effect=[login_response, first_server_error, second_server_error],
    ) as mock_json_request:
        assert connector._json_api_login() is False

    assert mock_json_request.call_count == 3
    assert connector._page_fetcher.has_bearer_token() is False
    assert connector._json_session_id is None
    assert connector._json_session_refreshed_at is None


@pytest.mark.parametrize("switch_model", JSON_API_MODEL_CLASSES)
def test_json_api_fetch_continues_after_keepalive_connection_error(
    switch_model: type[AutodetectedSwitchModel],
) -> None:
    """Allow the data request to proceed after a transient keepalive failure."""
    helper = JsonApiTestHelper(switch_model.MODEL_NAME)
    connector = NetgearSwitchConnector(host="switch.test", password="password")
    connector._set_instance_attributes_by_model(switch_model())
    connector._json_session_id = "active-session"
    connector._json_session_refreshed_at = 0
    port_response = helper.make_json_response(helper.data_dir / "0" / "ports.json")

    with (
        patch("py_netgear_plus.time.monotonic", return_value=60),
        patch.object(
            connector._page_fetcher,
            "json_request",
            side_effect=[PageFetcherConnectionError, port_response],
        ),
    ):
        result = connector._json_api_fetch(switch_model.PORT_STATUS_TEMPLATES)

    assert result is port_response
    assert connector._json_session_refreshed_at == 0


@pytest.mark.parametrize(
    ("switch_model", "expected_ports"),
    JSON_API_MODELS,
)
def test_json_api_autodetect_model(
    switch_model: type[AutodetectedSwitchModel],
    expected_ports: int,
) -> None:
    """Test autodetect_model for JSON REST API switches."""
    helper = JsonApiTestHelper(switch_model.MODEL_NAME)
    connector = NetgearSwitchConnector(host="192.168.0.1", password="password")
    with patch.object(
        connector._page_fetcher, "json_request", side_effect=helper.mock_json_request
    ):
        connector.autodetect_model()
    assert isinstance(connector.switch_model, switch_model)
    assert connector.switch_model.MODEL_NAME == switch_model.MODEL_NAME
    assert connector.ports == expected_ports


@pytest.mark.parametrize(
    ("switch_model", "expected_ports"),
    JSON_API_MODELS,
)
def test_json_api_get_login_cookie(
    switch_model: type[AutodetectedSwitchModel],
    expected_ports: int,  # noqa: ARG001
) -> None:
    """Test get_login_cookie for JSON REST API switches."""
    helper = JsonApiTestHelper(switch_model.MODEL_NAME)
    connector = NetgearSwitchConnector(host="192.168.0.1", password="password")
    with patch.object(
        connector._page_fetcher, "json_request", side_effect=helper.mock_json_request
    ):
        connector.autodetect_model()
        assert connector.get_login_cookie() is True
        assert connector._page_fetcher.has_bearer_token() is True
        assert connector._json_session_id is not None
        assert connector._json_session_refreshed_at is not None
        # Second call should return True without re-login
        assert connector.get_login_cookie() is True


@pytest.mark.parametrize(
    ("switch_model", "expected_ports"),
    JSON_API_MODELS,
)
def test_json_api_delete_login_cookie(
    switch_model: type[AutodetectedSwitchModel],
    expected_ports: int,  # noqa: ARG001
) -> None:
    """Test delete_login_cookie for JSON REST API switches."""
    helper = JsonApiTestHelper(switch_model.MODEL_NAME)
    connector = NetgearSwitchConnector(host="192.168.0.1", password="password")
    with patch.object(
        connector._page_fetcher, "json_request", side_effect=helper.mock_json_request
    ):
        connector.autodetect_model()
        connector.get_login_cookie()
    assert connector._page_fetcher.has_bearer_token() is True
    connector.delete_login_cookie()
    assert connector._page_fetcher.has_bearer_token() is False
    assert connector._json_session_id is None
    assert connector._json_session_refreshed_at is None


@pytest.mark.parametrize(
    ("switch_model", "expected_ports"),
    JSON_API_MODELS,
)
def test_json_api_get_unique_id(
    switch_model: type[AutodetectedSwitchModel],
    expected_ports: int,  # noqa: ARG001
) -> None:
    """Test get_unique_id for JSON REST API switches."""
    connector = NetgearSwitchConnector(host="192.168.0.1", password="password")
    connector.switch_model = switch_model
    expected = f"{switch_model.MODEL_NAME.lower()}_192_168_0_1"
    assert connector.get_unique_id() == expected


@pytest.mark.parametrize(
    ("switch_model", "expected_ports"),
    JSON_API_MODELS,
)
def test_json_api_get_switch_infos(
    switch_model: type[AutodetectedSwitchModel],
    expected_ports: int,  # noqa: ARG001
) -> None:
    """Test get_switch_infos for JSON REST API switches."""
    helper = JsonApiTestHelper(switch_model.MODEL_NAME)
    with patch("py_netgear_plus.time.perf_counter", return_value=0):
        connector = NetgearSwitchConnector(host="192.168.0.1", password="password")
        with patch.object(
            connector._page_fetcher,
            "json_request",
            side_effect=helper.mock_json_request,
        ):
            connector.autodetect_model()
            connector.get_login_cookie()

        for sequence in range(2):
            with patch.object(
                connector._page_fetcher,
                "json_request",
                side_effect=helper.mock_json_request,
            ):
                switch_data = connector.get_switch_infos()
            with Path(
                f"pages/{switch_model.MODEL_NAME}/{sequence}/switch_infos.json"
            ).open() as file:
                validation_data = json.loads(file.read())
                assert switch_data == validation_data
            helper.next_sequence()


def test_fetch_page_from_templates_timeout_backs_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Timeout-shaped failure retries via backoff, not via get_login_cookie."""
    connector = NetgearSwitchConnector(host="192.168.0.1", password="password")
    connector.switch_model = GS308EP()
    connector.RETRY_BACKOFF_SECONDS = 0  # speed test

    calls = {"count": 0}
    good = BaseResponse()
    good.status_code = requests.codes.ok
    good.content = b"OK"
    bad = BaseResponse()
    bad.status_code = None  # simulate timeout
    bad.content = b""

    def fake_fetch(*_a: object, **_kw: object) -> BaseResponse:
        calls["count"] += 1
        return bad if calls["count"] == 1 else good

    relogin_called = {"count": 0}

    def fake_login() -> bool:
        relogin_called["count"] += 1
        return True

    monkeypatch.setattr(connector, "fetch_page", fake_fetch)
    monkeypatch.setattr(connector, "get_login_cookie", fake_login)

    result = connector.fetch_page_from_templates(
        [{"method": "get", "url": "http://{ip}/vlan.cgi"}]
    )
    assert result is good
    assert calls["count"] == 2
    assert relogin_called["count"] == 0  # timeout path must not re-login


def test_parse_vlan_status_gs308ep() -> None:
    """Parse the captured GS308EP vlan.cgi page."""
    from py_netgear_plus.parsers import GS30xSeries as GS30xParser  # noqa: PLC0415

    page = Mock()
    page.status_code = requests.codes.ok
    page.content = Path("pages/GS308EP/0/vlan.cgi").read_bytes()
    parser = GS30xParser()
    result = parser.parse_vlan_status(page)
    assert result["mode"] == "adv8021Q"
    assert set(result["vlans"].keys()) >= {1, 100}
    assert result["vlans"][100]["name"] == "Internal"
    assert result["vlans"][100]["cfg"][1] == "E"
    assert result["vlans"][100]["cfg"][2] == "T"
    # Ports 3..8 should be Untagged members of VLAN 100 per captured state.
    for port in range(3, 9):
        assert result["vlans"][100]["cfg"][port] == "U"
    assert set(result["ports"].keys()) == set(range(1, 9))


def test_vlan_calls_raise_on_unsupported_model() -> None:
    """Switches without VLAN templates must raise NotImplementedError."""
    connector = NetgearSwitchConnector(host="192.168.0.1", password="password")
    # Default switch_model is AutodetectedSwitchModel — all VLAN template
    # class vars are empty.
    with pytest.raises(NotImplementedError):
        connector.vlan_status()
    with pytest.raises(NotImplementedError):
        connector.set_vlan_mode("adv8021Q")
    with pytest.raises(NotImplementedError):
        connector.add_vlan(100, "x", "U" * 8)
    with pytest.raises(NotImplementedError):
        connector.edit_vlan(1, "x", "U" * 8)
    with pytest.raises(NotImplementedError):
        connector.remove_vlan(1)
    with pytest.raises(NotImplementedError):
        connector.set_vlan_pvid(1, 1)


def _make_connector_for_vlan(current: dict) -> NetgearSwitchConnector:
    """
    Build a connector with VLAN methods mocked.

    `current` is what vlan_status() will return.
    """
    connector = NetgearSwitchConnector(host="192.168.0.1", password="password")
    connector.vlan_status = Mock(return_value=current)  # type: ignore[method-assign]
    connector.set_vlan_mode = Mock(return_value=True)  # type: ignore[method-assign]
    connector.add_vlan = Mock(return_value=True)  # type: ignore[method-assign]
    connector.edit_vlan = Mock(return_value=True)  # type: ignore[method-assign]
    connector.remove_vlan = Mock(return_value=True)  # type: ignore[method-assign]
    connector.set_vlan_pvid = Mock(return_value=True)  # type: ignore[method-assign]
    return connector


def _ports_cfg(letters: str) -> dict[int, str]:
    """Convert 'TUUUUUUE' to {1: 'T', 2: 'U', ...}."""
    return {i + 1: c for i, c in enumerate(letters)}


def test_apply_vlan_config_noop() -> None:
    """Identical config should trigger no mutating calls."""
    current = {
        "mode": "adv8021Q",
        "vlans": {
            1: {"name": "default", "members": [1], "cfg": _ports_cfg("UUUUUUUU")},
        },
        "ports": {p: {"name": f"p{p}", "pvid": 1, "vlans": {}} for p in range(1, 9)},
    }
    connector = _make_connector_for_vlan(current)
    config = {
        "mode": "adv8021Q",
        "vlans": {1: {"name": "default", "ports_config": "UUUUUUUU"}},
        "pvids": dict.fromkeys(range(1, 9), 1),
    }
    summary = connector.apply_vlan_config(config)
    connector.set_vlan_mode.assert_not_called()
    connector.add_vlan.assert_not_called()
    connector.edit_vlan.assert_not_called()
    connector.remove_vlan.assert_not_called()
    connector.set_vlan_pvid.assert_not_called()
    assert summary["added"] == []
    assert summary["edited"] == []
    assert summary["pvids_set"] == []


def test_apply_vlan_config_add_and_pvid() -> None:
    """Missing VLAN should be added, differing PVIDs set."""
    current = {
        "mode": "adv8021Q",
        "vlans": {
            1: {"name": "default", "members": [1], "cfg": _ports_cfg("UUUUUUUU")},
        },
        "ports": {p: {"name": f"p{p}", "pvid": 1, "vlans": {}} for p in range(1, 9)},
    }
    connector = _make_connector_for_vlan(current)
    config = {
        "mode": "adv8021Q",
        "vlans": {
            1: {"name": "default", "ports_config": "UUUUUUUU"},
            100: {"name": "Internal", "ports_config": "TUUUUUUE"},
        },
        "pvids": {2: 100, 3: 100},
    }
    summary = connector.apply_vlan_config(config)
    connector.add_vlan.assert_called_once_with(100, "Internal", "TUUUUUUE", False, 6)  # noqa: FBT003
    assert connector.set_vlan_pvid.call_count == 2
    assert summary["added"] == [100]
    assert sorted(summary["pvids_set"]) == [(2, 100), (3, 100)]


def test_apply_vlan_config_edit_when_ports_differ() -> None:
    """VLAN with same id but different membership should be edited."""
    current = {
        "mode": "adv8021Q",
        "vlans": {
            100: {
                "name": "Internal",
                "members": [1],
                "cfg": _ports_cfg("TUUUUUUE"),
            },
        },
        "ports": {p: {"name": f"p{p}", "pvid": 1, "vlans": {}} for p in range(1, 9)},
    }
    connector = _make_connector_for_vlan(current)
    config = {
        "mode": "adv8021Q",
        "vlans": {100: {"name": "Internal", "ports_config": "TUUUUUUU"}},
    }
    summary = connector.apply_vlan_config(config)
    connector.edit_vlan.assert_called_once()
    assert summary["edited"] == [100]


def test_apply_vlan_config_strict_removes_and_keeps_vlan1() -> None:
    """strict=True removes extras except VLAN 1 (unless listed)."""
    current = {
        "mode": "adv8021Q",
        "vlans": {
            1: {"name": "default", "members": [1], "cfg": _ports_cfg("UUUUUUUU")},
            200: {"name": "Guest", "members": [2], "cfg": _ports_cfg("UUUUUUUU")},
            300: {"name": "Other", "members": [3], "cfg": _ports_cfg("UUUUUUUU")},
        },
        "ports": {p: {"name": f"p{p}", "pvid": 1, "vlans": {}} for p in range(1, 9)},
    }
    connector = _make_connector_for_vlan(current)
    config = {
        "mode": "adv8021Q",
        "vlans": {200: {"name": "Guest", "ports_config": "UUUUUUUU"}},
    }
    summary = connector.apply_vlan_config(config, strict=True)
    connector.remove_vlan.assert_called_once_with(300)
    assert summary["removed"] == [300]
    assert 1 in summary["skipped"]


def test_apply_vlan_config_tracks_failures() -> None:
    """When a sub-call returns False, the operation lands in summary['failed']."""
    current = {
        "mode": "adv8021Q",
        "vlans": {
            1: {"name": "default", "members": [1], "cfg": _ports_cfg("UUUUUUUU")},
        },
        "ports": {p: {"name": f"p{p}", "pvid": 1, "vlans": {}} for p in range(1, 9)},
    }
    connector = _make_connector_for_vlan(current)
    connector.add_vlan = Mock(return_value=False)  # type: ignore[method-assign]
    config = {
        "mode": "adv8021Q",
        "vlans": {
            1: {"name": "default", "ports_config": "UUUUUUUU"},
            100: {"name": "Internal", "ports_config": "TUUUUUUE"},
        },
    }
    summary = connector.apply_vlan_config(config)
    assert summary["added"] == []
    assert ("add", 100) in summary["failed"]


def test_apply_vlan_config_order_pvid_before_edit() -> None:
    """Edits must be issued after PVIDs to avoid the silent-200 quirk."""
    current = {
        "mode": "adv8021Q",
        "vlans": {
            1: {"name": "default", "members": [1], "cfg": _ports_cfg("UUUUUUUU")},
            100: {"name": "Internal", "members": [2], "cfg": _ports_cfg("EUUUUUUU")},
        },
        "ports": {p: {"name": f"p{p}", "pvid": 1, "vlans": {}} for p in range(1, 9)},
    }
    connector = _make_connector_for_vlan(current)
    call_order: list[str] = []
    connector.edit_vlan = Mock(  # type: ignore[method-assign]
        side_effect=lambda *_a, **_kw: call_order.append("edit") or True
    )
    connector.set_vlan_pvid = Mock(  # type: ignore[method-assign]
        side_effect=lambda *_a, **_kw: call_order.append("pvid") or True
    )
    config = {
        "mode": "adv8021Q",
        "vlans": {
            1: {"name": "default", "ports_config": "UEEEEEEE"},
            100: {"name": "Internal", "ports_config": "EUUUUUUU"},
        },
        "pvids": {2: 100, 3: 100},
    }
    connector.apply_vlan_config(config)
    # Every "pvid" must appear before any "edit".
    assert "pvid" in call_order
    assert "edit" in call_order
    assert call_order.index("edit") > max(
        i for i, op in enumerate(call_order) if op == "pvid"
    )


def test_apply_vlan_config_switches_mode() -> None:
    """Mode mismatch should call set_vlan_mode and re-fetch status."""
    states = [
        {"mode": "noVlan", "vlans": {}, "ports": {}},
        {
            "mode": "adv8021Q",
            "vlans": {
                1: {
                    "name": "default",
                    "members": [1],
                    "cfg": _ports_cfg("UUUUUUUU"),
                },
            },
            "ports": {
                p: {"name": f"p{p}", "pvid": 1, "vlans": {}} for p in range(1, 9)
            },
        },
    ]
    connector = _make_connector_for_vlan(states[0])
    connector.vlan_status = Mock(side_effect=states)  # type: ignore[method-assign]
    config = {
        "mode": "adv8021Q",
        "vlans": {1: {"name": "default", "ports_config": "UUUUUUUU"}},
    }
    connector.apply_vlan_config(config)
    connector.set_vlan_mode.assert_called_once_with("adv8021Q")


def test_vlan_member_enum_roundtrip() -> None:
    """VLANMember value is the letter; web_code and from_web_code match."""
    from py_netgear_plus.models import VLANMember  # noqa: PLC0415

    assert VLANMember.TAGGED == "T"
    assert VLANMember.UNTAGGED == "U"
    assert VLANMember.EXCLUDED == "E"
    assert VLANMember.TAGGED.name.capitalize() == "Tagged"
    assert VLANMember.TAGGED.web_code == "1"
    assert VLANMember.UNTAGGED.web_code == "2"
    assert VLANMember.EXCLUDED.web_code == "3"
    for code in ("1", "2", "3"):
        assert VLANMember.from_web_code(code).web_code == code


def test_set_vlan_pvid_decodes_short_response(monkeypatch: pytest.MonkeyPatch) -> None:
    """Short '@port@vlan@' response triggers PortNotVLANMemberError."""
    from py_netgear_plus import PortNotVLANMemberError  # noqa: PLC0415

    connector = NetgearSwitchConnector(host="192.168.0.1", password="password")
    connector.switch_model = GS308EP()
    connector._client_hash = "deadbeef"

    fake_resp = Mock()
    fake_resp.status_code = requests.codes.ok
    fake_resp.content = b"@2@(100)"

    monkeypatch.setattr(
        connector._page_fetcher, "request", lambda *_a, **_kw: fake_resp
    )
    monkeypatch.setattr(
        connector._page_fetcher,
        "set_data_from_template",
        lambda *_a, **_kw: None,
    )
    with pytest.raises(PortNotVLANMemberError):
        connector.set_vlan_pvid(2, 100)


def _mock_page(path: str) -> Mock:
    """Build a Mock response wrapping fixture bytes."""
    page = Mock()
    page.status_code = requests.codes.ok
    page.content = Path(path).read_bytes()
    return page


def test_parse_port_settings_gs308ep() -> None:
    """Per-port settings parser returns one row per port with expected fields."""
    from py_netgear_plus.parsers import GS30xSeries as GS30xParser  # noqa: PLC0415

    result = GS30xParser().parse_port_settings(
        _mock_page("pages/GS308EP/0/dashboard.cgi")
    )
    assert set(result) == set(range(1, 9))
    # Port 1 of this fixture is named 'wax610b'.
    assert result[1]["name"] == "wax610b"
    for info in result.values():
        assert set(info) == {
            "name",
            "speed",
            "ingress_rate",
            "egress_rate",
            "flow_control",
        }


def test_parse_ip_config_gs308ep() -> None:
    """IP/DHCP parser pulls dhcp flag + addresses from ip_dhcp.cgi."""
    from py_netgear_plus.parsers import GS30xSeries as GS30xParser  # noqa: PLC0415

    result = GS30xParser().parse_ip_config(_mock_page("pages/GS308EP/0/ip_dhcp.cgi"))
    assert result == {
        "dhcp": True,
        "ip_address": "10.156.22.73",
        "subnet_mask": "255.255.255.0",
        "gateway": "10.156.22.1",
    }


def test_parse_initial_password_hash_gs308ep() -> None:
    """Factory-state hash iframe parser pulls the hidden value."""
    from py_netgear_plus.parsers import GS30xSeries as GS30xParser  # noqa: PLC0415

    page = Mock()
    page.status_code = requests.codes.ok
    page.content = (
        b"<html><body><form>"
        b"<input type='hidden' name='hash' id='hashEle' value='abc123'>"
        b"</form></body></html>"
    )
    assert GS30xParser().parse_initial_password_hash(page) == "abc123"


def test_get_password_change_data_base64() -> None:
    """Password change builder Base64-encodes old + new passwords."""
    import base64  # noqa: PLC0415

    model = GS308EP()
    data = model.get_password_change_data("oldpw", "newpw!")
    assert data["oldPasswd"] == base64.b64encode(b"oldpw").decode()
    assert data["newPasswd"] == base64.b64encode(b"newpw!").decode()


def test_get_ip_config_data_static_and_dhcp() -> None:
    """IP-config builder maps dhcp bool to dhcpMode '0'/'1'."""
    model = GS308EP()
    static = model.get_ip_config_data(
        dhcp=False,
        ip_address="1.2.3.4",
        subnet_mask="255.255.255.0",
        gateway="1.2.3.1",
    )
    assert static == {
        "dhcpMode": "0",
        "ip_address": "1.2.3.4",
        "subnet_mask": "255.255.255.0",
        "gateway_address": "1.2.3.1",
    }
    dhcp = model.get_ip_config_data(
        dhcp=True, ip_address="", subnet_mask="", gateway=""
    )
    assert dhcp["dhcpMode"] == "1"


def test_capability_matrix() -> None:
    """New capability helpers true on GS30xEP family, false elsewhere."""
    from py_netgear_plus.models import (  # noqa: PLC0415
        GS305E,
        GS305EP,
        GS305EPP,
        GS308EP,
        GS308EPP,
        GS316EP,
        GS316EPP,
        GS108Ev3,
    )

    expected_true = (GS305EP, GS305EPP, GS308EP, GS308EPP)
    expected_false = (GS316EP, GS316EPP, GS108Ev3, GS305E)
    for cls in expected_true:
        m = cls()
        assert m.has_vlan_support(), cls.__name__
        assert m.has_port_naming(), cls.__name__
        assert m.has_ip_config(), cls.__name__
        assert m.has_password_change(), cls.__name__
    for cls in expected_false:
        m = cls()
        assert not m.has_vlan_support(), cls.__name__
        assert not m.has_port_naming(), cls.__name__
        assert not m.has_ip_config(), cls.__name__
        assert not m.has_password_change(), cls.__name__


if __name__ == "__main__":
    pytest.main()
