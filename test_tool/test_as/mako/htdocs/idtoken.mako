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
    <h1>IdToken</h1>
      <% alt = 0 %>
      <table border="1">
        <tr>
          <th>Claim</th><th>Value</th>
        </tr>
        % for key, val in table.items():
            <tr>
               <% alt += 1 %>
               <td>${key}</td>
               <td>${val}</td>
            </tr>
        % endfor
      </table>
    <br>
    To go back click this ${link(back)}.
  </body>
</html>