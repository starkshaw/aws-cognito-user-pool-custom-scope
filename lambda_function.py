import json
import urllib
import requests
import logging
from http.cookies import SimpleCookie
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    logger.info('Event: {}'.format(json.dumps(event)))
    try:
        if not 'username' in event or len(event['username']) == 0:
            raise Exception('Parameter \'username\' is required.')
        if not 'password' in event or len(event['password']) == 0:
            raise Exception('Parameter \'password\' is required.')
        if not 'client_id' in event or len(event['client_id']) == 0:
            raise Exception('Parameter \'client_id\' is required.')
        if not 'redirect_uri' in event or len(event['redirect_uri']) == 0:
            raise Exception('Parameter \'redirect_uri\' is required.')
        if not 'scope' in event or len(event['scope']) == 0:
            raise Exception('Parameter \'scope\' is required.')
        if not 'full_custom_domain_name' in event or len(event['full_custom_domain_name']) == 0:
            if not 'user_pool_domain_prefix' in event or len(event['user_pool_domain_prefix']) == 0 or not 'region' in event or len(event['region']) == 0:
                raise Exception(
                    'Missing parameters. Either \'full_custom_domain_name parameter\' is provided or both of \'user_pool_domain_prefix\' and \'region\' parameters are provided.')
            else:
                user_pool_url = 'https://{}.auth.{}.amazoncognito.com'.format(
                    event['user_pool_domain_prefix'], event['region'])
        else:
            if 'user_pool_domain_prefix' in event:
                logger.warning(
                    'Parameter \'full_custom_domain_name\' and \'user_pool_domain_prefix\' both exist. \'full_custom_domain_name\' is prioritized.')
            if 'region' in event:
                logger.warning(
                    'Parameter \'full_custom_domain_name\' and \'region\' both exist. \'full_custom_domain_name\' is prioritized.')
            user_pool_url = event['full_custom_domain_name']
    except Exception as e:
        logger.error('Error: {}'.format(e))
        error_msg = {
            'message': str(e)
        }
        return {
            'statusCode': 502,
            'body': json.dumps(error_msg)
        }
    user_pool_oauth_url = '{}/oauth2/authorize?client_id={}&redirect_uri={}&response_type=code&scope={}'.format(
        user_pool_url, event['client_id'], event['redirect_uri'], event['scope'])
    user_pool_login_url = '{}/login?client_id={}&redirect_uri={}&response_type=code&scope={}'.format(
        user_pool_url, event['client_id'], event['redirect_uri'], event['scope'])
    user_pool_token_url = '{}/oauth2/token'.format(user_pool_url)
    logger.info('Attempting to logging into {}'.format(user_pool_oauth_url))
    xsrf_response = requests.get(user_pool_oauth_url, allow_redirects=False)
    try:
        if xsrf_response.status_code != 302:
            logger.error('HTTP {}: {}'.format(
                xsrf_response.status_code, xsrf_response.text))
            raise Exception(
                'HTTP request failed when attempting to get the XSRF response.')
    except Exception as e:
        logger.error('Error: {}'.format(e))
        error_msg = {
            'message': str(e)
        }
        return {
            'statusCode': 502,
            'body': json.dumps(error_msg)
        }
    cookie_str = xsrf_response.headers['Set-Cookie']
    logger.info('Set-Cookie: {}'.format(cookie_str))
    cookie = SimpleCookie()
    cookie.load(cookie_str)
    cookie_dict = {key: value.value for key, value in cookie.items()}
    xsrf_token = cookie_dict['XSRF-TOKEN']
    logger.info('XSRF token: {}'.format(xsrf_token))
    logging_headers = {
        b'cookie': bytes(cookie_str, encoding='utf-8')
    }
    logging_body = {
        b'_csrf': bytes(xsrf_token, encoding='utf-8'),
        b'username': bytes(event['username'], encoding='utf-8'),
        b'password': bytes(event['password'], encoding='utf-8')
    }
    logger.info('Attempting to get authorization code via {}'.format(
        user_pool_login_url))
    get_authorization_code_response = requests.post(
        user_pool_login_url, data=logging_body, headers=logging_headers)
    try:
        if get_authorization_code_response.status_code != 200:
            logger.error('HTTP {}: {}'.format(
                get_authorization_code_response.status_code, get_authorization_code_response.text))
            raise Exception(
                'HTTP request failed when attempting to get the authorization code response.')
    except Exception as e:
        logger.error('Error: {}'.format(e))
        error_msg = {
            'message': str(e)
        }
        return {
            'statusCode': 502,
            'body': json.dumps(error_msg)
        }
    logger.info('Redirecting to: {}'.format(
        get_authorization_code_response.url))
    try:
        authorization_code = urllib.parse.parse_qs(urllib.parse.urlparse(
            get_authorization_code_response.url).query)['code'][0]
    except Exception as e:
        logger.error('Error: {}'.format(e))
        error_msg = {
            'message': str(e)
        }
        return {
            'statusCode': 502,
            'body': json.dumps(error_msg)
        }
    token_exchange_body = {
        b'grant_type': b'authorization_code',
        b'client_id': bytes(event['client_id'], encoding='utf-8'),
        b'code': bytes(authorization_code, encoding='utf-8'),
        b'redirect_uri': bytes(event['redirect_uri'], encoding='utf-8')
    }
    try:
        jwt_response = requests.post(
            user_pool_token_url, data=token_exchange_body)
        response = {
            'statusCode': jwt_response.status_code,
            'body': json.loads(jwt_response.text),
            'headers': dict(jwt_response.headers)
        }
        return response
    except Exception as e:
        logger.error('Error: {}'.format(e))
        error_msg = {
            'message': str(e)
        }
        return {
            'statusCode': 502,
            'body': json.dumps(error_msg)
        }
    
