<%!
    def link(url):
        return "<a href='%sreset'>link</a>" % url
%>

<!DOCTYPE html>

<html>
  <head>
    <title>HEART OAuth2 AS Test</title>
    <link rel="stylesheet" type="text/css" href="${base}/static/theme.css">
  </head>
  <body>
    <h1>HEART OAuth2 AS Test</h1>
    <h2>Sorry ! An unforseen error occured</h2>S
    <br>
    To go back to the list of tests click this link.<br>
    To go back click this ${link(htmlpage)}.
  </body>
</html>