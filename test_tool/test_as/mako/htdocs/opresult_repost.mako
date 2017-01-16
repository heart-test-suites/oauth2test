<!DOCTYPE html>

<html>
<head>
    <title>HEART OAuth2 AS Test</title>
    <link rel="stylesheet" type="text/css" href="${base}/static/theme.css">
</head>
<body onload="document.forms[0].submit()">
    <form class="repost" action="authz_post" method="post">
        <input type="hidden" name="fragment" id="frag" value="x"/>
        <script type="text/javascript">
            if(window.location.hash) {
                var hash = window.location.hash.substring(1); //Puts hash in variable, and removes the # character
                document.getElementById("frag").value = hash;
            }
        </script>
    </form>
</body>
</html>
