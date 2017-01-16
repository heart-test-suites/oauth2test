<%!
    def link(url):
        return "<a href='%s'>link</a>" % url
%>

<!DOCTYPE html>

<html>
  <head>
    <title>HEART OAuth2 AS Test</title>
    <link rel="stylesheet" type="text/css" href="${base}/static/theme.css">
  </head>
  <body>
    <h1>HEART OAuth2 AS Test</h1>
    ${note}
    <br>
    To continue click this ${link(url)}.<br>
    To go back click this ${link(back)}.
  </body>
</html>