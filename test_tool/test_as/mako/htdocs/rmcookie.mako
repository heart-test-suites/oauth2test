<%!
    def button(url):
        return "<a href='%s'>button</a>" % url
%>

<!DOCTYPE html>

<html>
  <head>
    <title>HEART OAuth2 AS Test</title>
    <link rel="stylesheet" type="text/css" href="${base}/static/theme.css">
  </head>
  <body>
        <h1>HEART OAuth2 AS Test</h1>
        At this point you have to remove all cookies you have received from
        your OAuth2 AS. This since this test is simulating you
        login in from a second device while still being logged in at the first.
        So please remove the cookies and then hit this
        ${button(url)} to continue.
  </body>
</html>