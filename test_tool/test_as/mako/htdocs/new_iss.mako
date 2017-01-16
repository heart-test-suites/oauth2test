<%
  def form_action(base):
        return '<form action="{}/create">'.format(base)
%>

<!DOCTYPE html>
<html>
<head>
  <title>OAuth2 Authorization Server Test Tool Configuration</title>
  <link rel="stylesheet" type="text/css" href="${base}/static/theme.css">
</head>
<body>
<h2>Oauth2 Authorization Server Test</h2>
<br>

<p class="info">
  This is a tool used for testing the compliance of an OAuth2 Authorization
  Server (AS)
  with the Oauth2 RFCs. In order to start testing you need to configure a test
  instance. Enter the issuer URL to the AS you want to test.
</p>
<div class="inp">
<br>
  ${form_action(base)}
<h3>Issuer URL (without .well-known):</h3>
<input type="text" name="iss">
<br>
<h3>An identifier of this specific configuration in the case that you want to
  have more then one</h3>
<input type="text" name="tag" value="default">
<br>
<p>
  Choose what your AS supports:
<table border="1">
  <tr>
    <th>WebFinger</th>
    <td style="width:30px"><input type="checkbox" name="webfinger"></td>
  </tr>
</table>
<input type="hidden" name="discovery" value="on">
<input type="hidden" name="registration" value="'on">
<br>
<h3>Choose a response type</h3>
<br>
<table broder="1">
  <tr>
    <th style="width:200px">Response type</th>
    <td>
      <input type="radio" name="return_type" value="C"> Code <br>
      <input type="radio" name="return_type" value="T"> Token <br>
    </td>
  </tr>
</table>
</p>
  </div>
<button type="submit" value="Submit" class="button">Submit</button>
</form>
</body>
</html>