<%
import os

def display_log(base, logs, issuer, tag):
    if issuer:
        if tag:
            el = "<h3>List of tests that are saved on disk for this configuration:</h3>"
        else:
            el = "<h3>List of configurations that are saved on disk for this issuer:</h3>"
    else:
        el = "<h3>List of issuers that are saved on disk for this test server:</h3>"

    el += "<ul>"

    if tag:
        for name, path in logs:
            el += '<li><a href="{}{}" download="{}/{}.html">{}</a>'.format(
                base, path, issuer, name, name)
    elif issuer:
        for name, path in logs:
            _tarfile = "{}{}.tar".format(base, path.replace("log", "tar"))
            el += '<li><a href="{}{}">{}</a> tar file:<a href="{}">Download logs</a>'.format(
                base, path, name, _tarfile)
    else:
        for name, path in logs:
            el += '<li><a href="{}{}">{}</a>'.format(base, path, name)
    el += "</ul>"
    return el
%>

<!DOCTYPE html>
<html>
  <head>
    <title>HEART Oauth2 AS Test</title>
    <link rel="stylesheet" type="text/css" href="${base}/static/theme.css">
  </head>
  <body>
    <h1>HEART OAuth2 AS Test logs</h1>
        ${display_log(base, logs, issuer, profile)}
    ${postfix(base)}
  </body>
</html>