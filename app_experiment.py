import logging, requests
from flask import Flask, current_app, render_template, redirect, url_for, request, g
from flask_session import Session
from pathlib import Path
import app_config
from flask_cors import CORS


# https://github.com/azure-samples/ms-identity-python-samples-common



from ms_identity_web import IdentityWebPython
from ms_identity_web.adapters import FlaskContextAdapter
from ms_identity_web.errors import NotAuthenticatedError
from ms_identity_web.configuration import AADConfig

"""
Instructions for running the sample app. These are dev environment instructions ONLY.
Do not run using this configuration in production.

LINUX/OSX - in a terminal window, type the following:
=======================================================

    source venv/bin/activate
    export FLASK_APP=app.py
    export FLASK_ENV=development
    export FLASK_DEBUG=1
    export FLASK_RUN_CERT=adhoc
    flask run

WINDOWS - in a command window, type the following:
====================================================
    $env:FLASK_APP="app.py"
    $env:FLASK_ENV="development"
    $env:FLASK_DEBUG="1"
    $env:FLASK_RUN_CERT="adhoc"
    flask run

You can also use "python -m flask run" instead of "flask run"
"""

def create_app(secure_client_credential=None):
    app = Flask(__name__, root_path=Path(__file__).parent) #initialize Flask app
    CORS(app)
    app.config.from_object(app_config) # load Flask configuration file (e.g., session configs)
    Session(app) # init the serverside session for the app: this is requireddue to large cookie size
    # tell flask to render the 401 template on not-authenticated error. it is not strictly required:
    app.register_error_handler(NotAuthenticatedError, lambda err: (render_template('auth/401.html'), err.code))
    # comment out the previous line and uncomment the following line in order to use (experimental) <redirect to page after login>
    # app.register_error_handler(NotAuthenticatedError, lambda err: (redirect(url_for('auth.sign_in', post_sign_in_url=request.url_rule))))
    # other exceptions - uncomment to get details printed to screen:
    # app.register_error_handler(Exception, lambda err: (f"Error {err.code}: {err.description}"))
    aad_configuration = AADConfig.parse_json('aad.config.json') # parse the aad configs
    app.logger.level=logging.INFO # can set to DEBUG for verbose logs
    if app.config.get('ENV') == 'production':
        # The following is required to run on Azure App Service or any other host with reverse proxy:
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

        # Use client credential from outside the config file, if available.
        if secure_client_credential: 
            aad_configuration.client.client_credential = secure_client_credential

    # From readMe of common module
    # hook up the utils to your flask app:

    AADConfig.sanity_check_configs(aad_configuration)
    adapter = FlaskContextAdapter(app) # ms identity web for python: instantiate the flask adapter
    ms_identity_web = IdentityWebPython(aad_configuration, adapter) # then instantiate ms identity web for python




    @app.route('/')
    @app.route('/sign_in_status')
    def index():
        print("ENTRY TO DEBUG");
        return render_template('auth/status.html')

    # Associated to ~/goco/archives/gocoauth Angular code


    @app.route('/test3')
    def test3():
        print("In test3")
        bearer = request.headers['Bearer']
        print(bearer)
        graph = app.config['GRAPH_ME_ENDPOINT']
        token = f'Bearer {bearer}'
        print("URL to graph:", graph)
        # return {'success': True}
        results = requests.get("https://graph.microsoft.com/beta/me/", headers={
            'Authorization': token, 
            "Content-Type": "application/x-www-form-urlencoded"
            }).json()
        print("----------------------------------------------------------")
        print(results)
        return results

    @app.route('/test2')
    def test2():
        return { 'success': True}
        # print("In test2")
        # bearer = request.headers['Bearer']
        # print(bearer)
        # data = {'grant_type': 'client_credentials', 'client_id': CLIENTID, 'client_secret': SECRET, 'resource': APPURI}

        # r = requests.get("https://login.microsoftonline.com/8f70c1ad-9357-4fe5-9a60-2df469edebc2/oauth2/v2.0/token",
        #     headers=dict(Authorization="Bearer " + bearer, data))
        # print(r.json())
        # return r.json()
       

    @app.route('/test1')
    def test1():
        print("test1")
        # From studio3 source code
        # url = 'https://login.microsoftonline.com/8f70c1ad-9357-4fe5-9a60-2df469edebc2/v2.0'
        # client_id = '678c34b8-6652-4541-aadc-b806ae70da7f'
        # client_secret = 'R~HOR7T3CD8j_i8v~98z~8Vr93ecTeX576'
        # header_prefix ='Bearer-az2'

        azure_admin_login_url = 'https://login.microsoftonline.com/8f70c1ad-9357-4fe5-9a60-2df469edebc2/oauth2/v2.0/token'

        headers = {
            # TODO: Verify if 'Authorization' is needed here
            # "Authorization": 'Bearer ' + request.headers['Bearer'],
            "Content-Type": "application/x-www-form-urlencoded",
        }
        """
        {'grant_type': 'client_credentials', 
        'client_id': CLIENTID, 
        'client_secret': SECRET, 
        'resource': APPURI}
        """

        data = {
            'grant_type': 'client_credentials',
            'scope': 'https://graph.microsoft.com/.default',
            'client_id': '678c34b8-6652-4541-aadc-b806ae70da7f',
            'client_secret': 'R~HOR7T3CD8j_i8v~98z~8Vr93ecTeX576'
        }

        print("URL: ", azure_admin_login_url)
        print("HEADERS: ", headers)
        print("DATA: ", data)

        r = requests.post(azure_admin_login_url, headers, data)
        ret = r.json()
        if 'error' in ret:
            print("ERROR")
            print(ret)
            return {'success': False}
        print("SUCCESS")
        print(ret['error'].get('message'))
        return ret['error'].get('message')

        

    @app.route('/token_details')
    @ms_identity_web.login_required # <-- developer only needs to hook up login-required endpoint like this
    def token_details():
        current_app.logger.info("token_details: user is authenticated, will display token details")
        # return render_template('auth/token.html')
        return g.identity_context_data._id_token_claims
    
    @app.route("/call_ms_graph")
    @ms_identity_web.login_required
    def call_ms_graph():
        ms_identity_web.acquire_token_silently() 
        # graph = app.config['GRAPH_USERS_ENDPOINT']
        graph = app.config['GRAPH_ME_ENDPOINT']
        token = f'Bearer {ms_identity_web.id_data._access_token}'
        print("URL to graph:", graph)
        results = requests.get(graph, headers={'Authorization': token}).json()
        # return render_template('auth/call-graph.html', results=results)
        return results

    return app

if __name__ == '__main__':
    app=create_app() # this is for running flask's dev server for local testing purposes ONLY
    # app.run(ssl_context='adhoc') # create an adhoc ssl cert for HTTPS on 127.0.0.1
    app.run() # create an adhoc ssl cert for HTTPS on 127.0.0.1

app=create_app()
