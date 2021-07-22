import json
import urllib
from typing import Any, Dict, Union

import requests
import logging
from http.cookies import SimpleCookie

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event: Any, context: Any
                   ) -> Union[Dict[str, Union[int, str]], Dict[str, Union[Dict[Any, Any], dict]]]:
    logger.info("Event: {}".format(json.dumps(event)))

    try:
        if not are_required_params_passed(event, context):
            raise Exception(
                "Parameters: username, password, client_id, redirect_uri and scope are required."
            )

        user_pool_url = create_user_pool_url(event, context)

    except Exception as e:
        return return_on_error(e)

    user_pool_oauth_url = "{}/oauth2/authorize?client_id={}&redirect_uri={}&response_type=code&scope={}".format(
        user_pool_url, event["client_id"], event["redirect_uri"], event["scope"]
    )

    user_pool_login_url = (
        "{}/login?client_id={}&redirect_uri={}&response_type=code&scope={}".format(
            user_pool_url, event["client_id"], event["redirect_uri"], event["scope"]
        )
    )

    user_pool_token_url = "{}/oauth2/token".format(user_pool_url)
    logger.info("Attempting to logging into {}".format(user_pool_oauth_url))

    xsrf_response = requests.get(user_pool_oauth_url, allow_redirects=False)

    try:
        if xsrf_response.status_code != 302:
            logger.error(
                "HTTP {}: {}".format(xsrf_response.status_code, xsrf_response.text)
            )
            raise Exception(
                "HTTP request failed when attempting to get the XSRF response."
            )

    except Exception as e:
        return return_on_error(e)

    cookie_str = xsrf_response.headers["Set-Cookie"]
    logger.info("Set-Cookie: {}".format(cookie_str))

    cookie = SimpleCookie()
    cookie.load(cookie_str)
    cookie_dict = {key: value.value for key, value in cookie.items()}
    xsrf_token = cookie_dict["XSRF-TOKEN"]
    logger.info("XSRF token: {}".format(xsrf_token))
    logging_headers = {b"cookie": bytes(cookie_str, encoding="utf-8")}
    logging_body = {
        b"_csrf": bytes(xsrf_token, encoding="utf-8"),
        b"username": bytes(event["username"], encoding="utf-8"),
        b"password": bytes(event["password"], encoding="utf-8"),
    }

    logger.info(
        "Attempting to get authorization code via {}".format(user_pool_login_url)
    )

    get_authorization_code_response = requests.post(
        user_pool_login_url, data=logging_body, headers=logging_headers
    )

    try:
        if get_authorization_code_response.status_code != 200:
            logger.error(
                "HTTP {}: {}".format(
                    get_authorization_code_response.status_code,
                    get_authorization_code_response.text,
                )
            )
            raise Exception(
                "HTTP request failed when attempting to get the authorization code response."
            )

    except Exception as e:
        return return_on_error(e)

    logger.info("Redirecting to: {}".format(get_authorization_code_response.url))

    try:
        authorization_code = urllib.parse.parse_qs(
            urllib.parse.urlparse(get_authorization_code_response.url).query
        )["code"][0]

    except Exception as e:
        return return_on_error(e)

    token_exchange_body = {
        b"grant_type": b"authorization_code",
        b"client_id": bytes(event["client_id"], encoding="utf-8"),
        b"code": bytes(authorization_code, encoding="utf-8"),
        b"redirect_uri": bytes(event["redirect_uri"], encoding="utf-8"),
    }

    try:
        jwt_response = requests.post(user_pool_token_url, data=token_exchange_body)

        response = {
            "statusCode": jwt_response.status_code,
            "body": json.loads(jwt_response.text),
            "headers": dict(jwt_response.headers),
        }

        return response

    except Exception as e:
        return return_on_error(e)


def are_required_params_passed(event: Any, context: Any) -> bool:
    """
    confirm that the required params are passed.
    :param event: lambda event.
    :param context: context
    :return: bool
    """
    required_params_in_event = [
        "username",
        "password",
        "client_id",
        "redirect_uri",
        "scope",
    ]  # related values passed as a json object with these attrs
    for required_attr in required_params_in_event:
        if not event[required_attr] or len(event[required_attr]) == 0:
            return False
    return True


def create_user_pool_url(event: Any, context: Any) -> str:
    """
    Create userpool url from params.
    :param event: lambda event
    :param context: context
    :return: str
    """
    if not event["full_custom_domain_name"] or not (
            event["user_pool_domain_prefix"] and event["region"]
    ):
        raise Exception(
            "Please provide either full_custom_domain_name or user_pool_domain_prefix and region"
        )

    return (
        event["full_custom_domain_name"]
        if event["full_custom_domain_name"]
        else "https://{}.auth.{}.amazoncognito.com".format(
            event["user_pool_domain_prefix"], event["region"]
        )
    )


def return_on_error(e: Any) -> Dict[str, Union[int, str]]:
    """
    Return immediately when error is encountered.
    :param e: error
    :return: dict of error attrs
    """
    logger.error("Error: {}".format(e))
    error_msg = {"message": str(e)}
    return {"statusCode": 502, "body": json.dumps(error_msg)}
