from flask import Flask, request, jsonify, redirect, url_for
from flask_cognito import CognitoAuth
import boto3
from botocore.exceptions import NoCredentialsError

app = Flask(__name__)

app.config['COGNITO_REGION'] = 'eu-west-2'
app.config['COGNITO_USERPOOL_ID'] = 'eu-west-2_8fhkQVpyq'
app.config['COGNITO_APP_CLIENT_ID'] = '6r5g84m87gfcqsormc7jh8fdjv'
# app.config['COGNITO_APP_CLIENT_SECRET'] = 'your-app-client-secret'

cognito = CognitoAuth(app)

# Initialize boto3 client for Cognito Identity Provider
cognito_client = boto3.client('cognito-idp', region_name=app.config['COGNITO_REGION'])

def send_verification_code(username):
    try:
        import pdb; pdb.set_trace()
        response = cognito_client.admin_create_user(
            UserPoolId=app.config['COGNITO_USERPOOL_ID'],
            Username=username,
            MessageAction='SUPPRESS'  # Avoid sending an invitation message
        )
        return response['User']['Username']
    except cognito_client.exceptions.UsernameExistsException:
        return None

@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    import pdb; pdb.set_trace()
    username = data['username']
    password = data['password']
    email = data['email']

    try:
        # Send a verification code to the user
        verification_username = send_verification_code(username)

        if verification_username:
            # Confirm the user with the provided password
            cognito_client.admin_confirm_sign_up(
                UserPoolId=app.config['COGNITO_USERPOOL_ID'],
                Username=verification_username,
                ConfirmationCode=data['confirmation_code']
            )

            return jsonify({'message': 'Signup successful'})
        else:
            return jsonify({'message': 'Username already exists'}), 400

    except cognito_client.exceptions.CodeMismatchException:
        return jsonify({'message': 'Invalid confirmation code'}), 401
    except Exception as e:
        print(f"Error during signup: {e}")
        return jsonify({'message': 'Signup failed'}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data['username']
    password = data['password']

    try:
        response = cognito_client.admin_initiate_auth(
            UserPoolId=app.config['COGNITO_USERPOOL_ID'],
            ClientId=app.config['COGNITO_APP_CLIENT_ID'],
            AuthFlow='ADMIN_NO_SRP_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password,
            }
        )

        return jsonify({'message': 'Login successful', 'access_token': response['AuthenticationResult']['AccessToken']})

    except cognito_client.exceptions.NotAuthorizedException:
        return jsonify({'message': 'Invalid credentials'}), 401
    except Exception as e:
        print(f"Error during login: {e}")
        return jsonify({'message': 'Login failed'}), 500

if __name__ == '__main__':
    app.run(debug=True)
