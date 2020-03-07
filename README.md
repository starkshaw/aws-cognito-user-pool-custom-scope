# aws-cognito-user-pool-custom-scope
A Lambda function allows you to retrieve tokens with custom scope from Cognito User Pool.

## External Dependencies

- [`requests`](https://github.com/psf/requests)

### How to install external dependencies?

- Creating a function deployment package by following the documentation [here](https://docs.aws.amazon.com/lambda/latest/dg/python-package.html#python-package-dependencies).
- Creating a Lambda layer by following the documentation [here](https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html#configuration-layers-path).

## Internal Dependencies

The following libraries are included in AWS Lambda Python runtimes:

- `json`
- `logging`
- `http`
- `urllib`

## Example Lambda Event

```
{
  "username": "",
  "password": "",
  "user_pool_domain_prefix": "",
  "region": "",
  "client_id": "",
  "redirect_uri": "",
  "scope": "",
  "full_custom_domain_name": ""
}
```

Either fill in `full_custom_domain_name` or fill in both `user_pool_domain_prefix` and `region`.

If all three fields are filled, `full_custom_domain_name` will be prioritized.

Other parameters are required. The app client should support code grant and have client secret disabled.

## Example Lambda Response

```
{
  "statusCode": 200,
  "body": {
    "id_token": "",
    "access_token": "",
    "refresh_token": "",
    "expires_in": 3600,
    "token_type": "Bearer"
  },
  "headers": {
    "Date": "",
    "Content-Type": "",
    "Transfer-Encoding": "",
    "Connection": "",
    "Set-Cookie": "",
    "x-amz-cognito-request-id": "",
    "X-Application-Context": "",
    "X-Content-Type-Options": "",
    "X-XSS-Protection": "",
    "Cache-Control": "",
    "Pragma": "",
    "Expires": "",
    "Strict-Transport-Security": "",
    "X-Frame-Options": "",
    "Server": ""
  }
}
```

If the authentication is successful, tokens will be stored inside `body`. The response headers returned are stored in `headers`.

## Logging

If the Lambda function has the following permission, it will send diagnostic logs to CloudWatch log:

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "logs:CreateLogGroup",
            "Resource": "arn:aws:logs:<region>:<account-id>:*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": [
                "arn:aws:logs:<region>:<account-id>:log-group:/aws/lambda/<lambda-function-name>:*"
            ]
        }
    ]
}
```

Lambda function created as of today will automatically generate an execution role with this IAM policy attached.

### Notice

If `INFO` level logging is not required or considered containing sensitive data, it is suggested to remove all `logging.info()` lines or change the logging level from `logger.setLevel(logging.INFO)` to `logger.setLevel(logging.ERROR)`, in which case only error logs will be sent to CloudWatch.