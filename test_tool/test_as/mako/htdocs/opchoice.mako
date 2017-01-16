<%!
def op_choice(op_list):
    """
    Creates a dropdown list of OAuth2 Authorization Servers
    """
    element = "<select name=\"op\">"
    for name in op_list:
        element += "<option value=\"%s\">%s</option>" % (name, name)
    element += "</select>"
    return element
%>

<!DOCTYPE html>

<html>
  <head>
    <title>HEART OAuth2 AS Test</title>
    <link rel="stylesheet" type="text/css" href="${base}/static/theme.css">
  </head>
  <body>
    <form class="form-signin" action="rp" method="get">
    <h1>AS by UID</h1>
      <h3>Chose the OAuth2 AS: </h3>
        <p>From this list</p>
        ${op_choice(op_list)}
        <p> OR by providing your unique identifier at the AS. </p>
        <input type="text" id="uid" name="uid" class="form-control" placeholder="UID" autofocus>
        <button class="btn btn-lg btn-primary btn-block" type="submit">Start</button>
    </form>
  </body>
</html>