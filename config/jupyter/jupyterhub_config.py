# Configuration file for jupyter single user server.

c = get_config()  # type: ignore

c.ServerApp.token = ""  # disable default token auth
c.ServerApp.password = ""  # no password
c.ServerApp.trust_xheaders = True

# custom authorizer
c.ServerApp.authorizer_class = "jwt_auth.jwt_authorizer.JWTAuthorizer"
c.ServerApp.root_dir = "/home/jovyan/notebooks"
