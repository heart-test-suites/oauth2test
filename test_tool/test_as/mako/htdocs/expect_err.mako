<%!
    def link(url):
        return "<a href='%s'>link</a>" % url
%>

<!DOCTYPE html>

<html>
  <head>
    <title>HEART OAuth2 AS Test</title>
  </head>
  <body>
    <h1>HEART OAuth2 AS Test</h1>
    <div class="inp">
      The next request should result in the OAuth2 Authorization Server
      returning an error message to your web browser. To continue click this
      ${link(url)}.
    </div>
  </body>
</html>