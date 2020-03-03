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

## Example Lambda Event:

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